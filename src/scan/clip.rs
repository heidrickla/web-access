//! Stands between the two clipboard endpoints of one session. An offer of files is never passed on
//! as it arrives: the proxy answers the sender itself, fetches the file list and every byte of
//! every file under its own stream ids, has each file scanned, and only when all are clean offers
//! them to the receiver, whose requests it then answers from the scanned copy. A refused offer
//! reaches the receiver as an empty clipboard. Clipboard data that is not a file list passes
//! through as it arrived.
//!
//! One task per session owns all of this; the relay hands it whole clipboard PDUs and writes what
//! it returns, so nothing here is shared between tasks.

use super::route::{Route, Whole};
use super::scanner::{Scanner, Verdict};
use ironrdp_cliprdr::pdu::{
    Capabilities, ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId,
    ClipboardGeneralCapabilityFlags, ClipboardPdu, FileContentsFlags, FileContentsRequest,
    FileContentsResponse, FileDescriptor, FormatDataRequest, FormatDataResponse, FormatList,
    FormatListResponse,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

/// The registered clipboard format that lists files (MS-RDPECLIP 1.3.1.2).
pub const FILE_LIST: &str = "FileGroupDescriptorW";
/// Bytes asked for in one file contents request.
const RANGE: u32 = 1 << 20;
/// How long the sender has to answer one request of the proxy's.
const ANSWER: Duration = Duration::from_secs(30);
/// Stream ids of the proxy's own requests start here, away from the endpoints' own counters.
const FIRST_STREAM: u32 = 0x5741_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// From the browser to the server.
    Upload,
    /// From the server to the browser.
    Download,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// Files are being fetched and scanned.
    Started {
        dir: Dir,
        files: Vec<(String, u64)>,
    },
    Passed {
        dir: Dir,
        files: Vec<(String, u64)>,
    },
    Refused {
        dir: Dir,
        files: Vec<(String, u64)>,
        reason: String,
    },
}

/// Bytes held for scanning across every session, and the most there may be.
pub struct Staging {
    held: AtomicU64,
    max: u64,
}

impl Staging {
    pub fn new(max: u64) -> Arc<Self> {
        Arc::new(Self {
            held: AtomicU64::new(0),
            max,
        })
    }

    fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        let mut held = self.held.load(Ordering::Acquire);
        loop {
            let next = held.checked_add(bytes).filter(|n| *n <= self.max)?;
            match self
                .held
                .compare_exchange(held, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(Reservation {
                        staging: Arc::clone(self),
                        bytes,
                    })
                }
                Err(now) => held = now,
            }
        }
    }

    #[cfg(test)]
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::Acquire)
    }
}

/// Released when the offer it holds room for is dropped.
struct Reservation {
    staging: Arc<Staging>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.staging.held.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub struct Context<'a> {
    pub scanner: Arc<dyn Scanner>,
    pub scan_timeout: Duration,
    /// Whether the scanner last proved it answers; an offer is refused while it has not.
    pub healthy: Arc<dyn Fn() -> Result<(), String> + Send + Sync + 'a>,
    /// The Settings tab's per-file limit, read when an offer arrives.
    pub max_file_bytes: Arc<dyn Fn() -> Option<u64> + Send + Sync + 'a>,
    pub staging: Arc<Staging>,
    pub report: Arc<dyn Fn(Report) + Send + Sync + 'a>,
}

pub enum Input {
    FromClient(Whole),
    FromServer(Whole),
    Scanned {
        dir: Dir,
        generation: u64,
        index: usize,
        verdict: Verdict,
    },
}

/// Bytes for one side, written in the order produced.
pub enum Output {
    ToClient(Vec<u8>),
    ToServer(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum ClipError {
    #[error(transparent)]
    Route(#[from] super::route::RouteError),
}

/// Who a request sent to a sender was for, so its answer goes to the same place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Receiver,
    Proxy,
}

struct Fetch {
    generation: u64,
    /// The sender's Format List, as it arrived: what the receiver is offered once the files pass.
    list: Vec<Vec<u8>>,
    file_list: ClipboardFormatId,
    step: Step,
    deadline: Instant,
    reservation: Option<Reservation>,
}

enum Step {
    Descriptor,
    Contents {
        descriptor: Vec<u8>,
        files: Vec<FileDescriptor>,
        data: Vec<Vec<u8>>,
        index: usize,
        stream: u32,
    },
    Scanning {
        descriptor: Vec<u8>,
        files: Vec<FileDescriptor>,
        data: Vec<Vec<u8>>,
        verdicts: Vec<Option<Verdict>>,
    },
}

struct Offer {
    file_list: ClipboardFormatId,
    descriptor: Vec<u8>,
    data: Vec<Vec<u8>>,
    _reservation: Option<Reservation>,
}

#[derive(Default)]
enum Phase {
    #[default]
    Idle,
    Fetching(Fetch),
    Offered(Offer),
}

#[derive(Default)]
struct Direction {
    phase: Phase,
    /// Answers the sender owes to Format Data Requests, oldest first.
    data_owed: VecDeque<Owner>,
    /// Answers the receiver owes to Format Lists, oldest first.
    lists_owed: VecDeque<Owner>,
}

pub struct Clip<'a> {
    ctx: Context<'a>,
    route: Arc<Mutex<Route>>,
    up: Direction,
    down: Direction,
    long_names: [bool; 2],
    generation: u64,
    next_stream: u32,
    out: Vec<Output>,
    scans: mpsc::Sender<Input>,
}

fn files_of(files: &[FileDescriptor]) -> Vec<(String, u64)> {
    files
        .iter()
        .map(|f| (f.name.clone(), f.file_size.unwrap_or(0)))
        .collect()
}

impl<'a> Clip<'a> {
    /// `scans` is this task's own input: scan verdicts come back through it.
    pub fn new(ctx: Context<'a>, route: Arc<Mutex<Route>>, scans: mpsc::Sender<Input>) -> Self {
        Self {
            ctx,
            route,
            up: Direction::default(),
            down: Direction::default(),
            long_names: [true, true],
            generation: 0,
            next_stream: FIRST_STREAM,
            out: Vec::new(),
            scans,
        }
    }

    /// Runs until the relay stops sending input. Writes go out through `write` in order.
    pub async fn run<F, Fut>(
        mut self,
        mut input: mpsc::Receiver<Input>,
        mut write: F,
    ) -> Result<(), ClipError>
    where
        F: FnMut(Output) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        loop {
            let deadline = self.deadline();
            tokio::select! {
                next = input.recv() => match next {
                    Some(i) => self.handle(i)?,
                    None => return Ok(()),
                },
                _ = sleep_until(deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))), if deadline.is_some() => {
                    self.expire()?;
                }
            }
            for o in std::mem::take(&mut self.out) {
                if !write(o).await {
                    return Ok(());
                }
            }
        }
    }

    fn deadline(&self) -> Option<Instant> {
        [&self.up, &self.down]
            .iter()
            .filter_map(|d| match &d.phase {
                Phase::Fetching(f) => Some(f.deadline),
                _ => None,
            })
            .min()
    }

    fn expire(&mut self) -> Result<(), ClipError> {
        self.expire_at(Instant::now())
    }

    fn expire_at(&mut self, now: Instant) -> Result<(), ClipError> {
        for dir in [Dir::Upload, Dir::Download] {
            let late =
                matches!(&self.direction(dir).phase, Phase::Fetching(f) if f.deadline <= now);
            if late {
                self.refuse(dir, "the sender or the scanner took too long")?;
            }
        }
        Ok(())
    }

    fn direction(&mut self, dir: Dir) -> &mut Direction {
        match dir {
            Dir::Upload => &mut self.up,
            Dir::Download => &mut self.down,
        }
    }

    fn long_names(&self) -> bool {
        self.long_names[0] && self.long_names[1]
    }

    // ---- writing ------------------------------------------------------------------------------

    fn send_sender(&mut self, dir: Dir, pdu: ClipboardPdu<'static>) -> Result<(), ClipError> {
        self.send(dir == Dir::Upload, pdu)
    }

    fn send_receiver(&mut self, dir: Dir, pdu: ClipboardPdu<'static>) -> Result<(), ClipError> {
        self.send(dir == Dir::Download, pdu)
    }

    fn send(&mut self, client: bool, pdu: ClipboardPdu<'static>) -> Result<(), ClipError> {
        let route = self.route.lock().unwrap_or_else(|p| p.into_inner());
        let bytes = if client {
            route.to_client(pdu)?
        } else {
            route.to_server(pdu)?
        };
        drop(route);
        self.out.push(if client {
            Output::ToClient(bytes)
        } else {
            Output::ToServer(bytes)
        });
        Ok(())
    }

    /// The units a PDU arrived in, passed on to the other side unchanged.
    fn pass(&mut self, from_client: bool, whole: Whole) {
        for unit in whole.units {
            self.out.push(if from_client {
                Output::ToServer(unit)
            } else {
                Output::ToClient(unit)
            });
        }
    }

    // ---- reading ------------------------------------------------------------------------------

    pub fn handle(&mut self, input: Input) -> Result<(), ClipError> {
        match input {
            Input::FromClient(w) => self.take(true, w),
            Input::FromServer(w) => self.take(false, w),
            Input::Scanned {
                dir,
                generation,
                index,
                verdict,
            } => self.scanned(dir, generation, index, verdict),
        }
    }

    fn take(&mut self, client: bool, whole: Whole) -> Result<(), ClipError> {
        // As sender: the direction its data travels. As receiver: the direction it asks about.
        let sending = if client { Dir::Upload } else { Dir::Download };
        let receiving = if client { Dir::Download } else { Dir::Upload };
        let bytes = whole.pdu.clone();
        let pdu = ironrdp_core::decode::<ClipboardPdu<'_>>(&bytes)
            .map_err(|e| super::route::RouteError::OutOfStep(e.to_string()))?;
        match pdu {
            ClipboardPdu::Capabilities(caps) => {
                // Neither side may lock clipboard data: the proxy answers from its own copy.
                let flags = caps.flags();
                self.long_names[usize::from(client)] =
                    flags.contains(ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
                let masked = Capabilities::new(
                    caps.version(),
                    flags - ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA,
                );
                let pdu = ClipboardPdu::Capabilities(masked);
                self.send(!client, pdu)
            }
            ClipboardPdu::FormatList(list) => self.format_list(sending, list, whole),
            ClipboardPdu::FormatListResponse(_) => {
                match self.direction(receiving).lists_owed.pop_front() {
                    Some(Owner::Proxy) => Ok(()),
                    _ => {
                        self.pass(client, whole);
                        Ok(())
                    }
                }
            }
            ClipboardPdu::FormatDataRequest(req) => {
                self.data_request(receiving, req, client, whole)
            }
            ClipboardPdu::FormatDataResponse(resp) => {
                match self.direction(sending).data_owed.pop_front() {
                    Some(Owner::Proxy) => self.descriptor(sending, resp),
                    _ => {
                        self.pass(client, whole);
                        Ok(())
                    }
                }
            }
            ClipboardPdu::FileContentsRequest(req) => self.contents_request(receiving, req),
            ClipboardPdu::FileContentsResponse(resp) => self.contents(sending, resp),
            // Locks were masked out; one arriving anyway locks nothing the proxy serves.
            ClipboardPdu::LockData(_) | ClipboardPdu::UnlockData(_) => Ok(()),
            ClipboardPdu::MonitorReady | ClipboardPdu::TemporaryDirectory(_) => {
                self.pass(client, whole);
                Ok(())
            }
        }
    }

    fn format_list(
        &mut self,
        dir: Dir,
        list: FormatList<'_>,
        whole: Whole,
    ) -> Result<(), ClipError> {
        // A new clipboard on the sender's side ends whatever was in progress for the old one.
        self.direction(dir).phase = Phase::Idle;
        let formats = list.get_formats(self.long_names()).unwrap_or_default();
        let Some(file_list) = file_list_format(&formats) else {
            self.direction(dir).lists_owed.push_back(Owner::Receiver);
            self.pass(dir == Dir::Upload, whole);
            return Ok(());
        };
        self.send_sender(
            dir,
            ClipboardPdu::FormatListResponse(FormatListResponse::Ok),
        )?;
        if let Err(why) = (self.ctx.healthy)() {
            (self.ctx.report)(Report::Refused {
                dir,
                files: Vec::new(),
                reason: format!("the scanner is not answering: {why}"),
            });
            return self.clear_receiver(dir);
        }
        self.generation += 1;
        self.direction(dir).phase = Phase::Fetching(Fetch {
            generation: self.generation,
            list: whole.units,
            file_list,
            step: Step::Descriptor,
            deadline: Instant::now() + ANSWER,
            reservation: None,
        });
        self.direction(dir).data_owed.push_back(Owner::Proxy);
        self.send_sender(
            dir,
            ClipboardPdu::FormatDataRequest(FormatDataRequest { format: file_list }),
        )
    }

    fn data_request(
        &mut self,
        dir: Dir,
        req: FormatDataRequest,
        client: bool,
        whole: Whole,
    ) -> Result<(), ClipError> {
        let answer = match &self.direction(dir).phase {
            Phase::Offered(o) if o.file_list == req.format => {
                Some(FormatDataResponse::new_data(o.descriptor.clone()))
            }
            // The receiver asks about a clipboard that has since changed.
            Phase::Fetching(_) => Some(FormatDataResponse::new_error()),
            _ => None,
        };
        match answer {
            Some(a) => self.send_receiver(dir, ClipboardPdu::FormatDataResponse(a)),
            None => {
                self.direction(dir).data_owed.push_back(Owner::Receiver);
                self.pass(client, whole);
                Ok(())
            }
        }
    }

    fn contents_request(&mut self, dir: Dir, req: FileContentsRequest) -> Result<(), ClipError> {
        let answer = match &self.direction(dir).phase {
            Phase::Offered(o) => usize::try_from(req.index)
                .ok()
                .and_then(|i| o.data.get(i))
                .map(|file| {
                    if req.flags.contains(FileContentsFlags::SIZE) {
                        FileContentsResponse::new_size_response(req.stream_id, file.len() as u64)
                    } else {
                        let start = usize::try_from(req.position)
                            .unwrap_or(usize::MAX)
                            .min(file.len());
                        let end = start
                            .saturating_add(req.requested_size as usize)
                            .min(file.len());
                        FileContentsResponse::new_data_response(
                            req.stream_id,
                            file[start..end].to_vec(),
                        )
                    }
                }),
            _ => None,
        };
        // Contents never come from the sender directly: anything not scanned is refused.
        let answer = answer.unwrap_or_else(|| FileContentsResponse::new_error(req.stream_id));
        self.send_receiver(dir, ClipboardPdu::FileContentsResponse(answer))
    }

    /// The sender's file list arrived.
    fn descriptor(&mut self, dir: Dir, resp: FormatDataResponse<'_>) -> Result<(), ClipError> {
        let limit = (self.ctx.max_file_bytes)();
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            return Ok(());
        };
        if !matches!(f.step, Step::Descriptor) {
            return Ok(());
        }
        if resp.is_error() {
            return self.refuse(dir, "the sender did not list its files");
        }
        let files = match resp.to_file_list() {
            Ok(l) => l.files,
            Err(_) => return self.refuse(dir, "the sender's file list could not be read"),
        };
        let descriptor = resp.data().to_vec();
        if files.is_empty() {
            return self.refuse(dir, "the offer holds no files");
        }
        if files.iter().any(|f| {
            f.relative_path.is_some()
                || f.attributes
                    .is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY))
        }) {
            return self.refuse_files(dir, &files, "folders are not transferred");
        }
        if files.iter().any(|f| f.file_size.is_none()) {
            return self.refuse_files(dir, &files, "a file came without its size");
        }
        let sizes: Vec<u64> = files.iter().map(|f| f.file_size.unwrap_or(0)).collect();
        if let Some(limit) = limit {
            if sizes.iter().any(|s| *s > limit) {
                return self.refuse_files(dir, &files, "larger than the file-size limit");
            }
        }
        let total: u64 = sizes.iter().sum();
        let Some(reservation) = self.ctx.staging.reserve(total) else {
            return self.refuse_files(dir, &files, "too much is being scanned at once");
        };
        (self.ctx.report)(Report::Started {
            dir,
            files: files_of(&files),
        });
        let stream = self.next_stream();
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            return Ok(());
        };
        f.reservation = Some(reservation);
        let data = sizes
            .iter()
            .map(|s| Vec::with_capacity(usize::try_from(*s).unwrap_or(0)))
            .collect();
        f.step = Step::Contents {
            descriptor,
            files,
            data,
            index: 0,
            stream,
        };
        self.fetch_next(dir)
    }

    fn next_stream(&mut self) -> u32 {
        let s = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1).max(FIRST_STREAM);
        s
    }

    /// Asks for the next range, or starts the scans once every byte is in.
    fn fetch_next(&mut self, dir: Dir) -> Result<(), ClipError> {
        let scan_timeout = self.ctx.scan_timeout;
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            return Ok(());
        };
        let Step::Contents {
            files,
            data,
            index,
            stream,
            ..
        } = &mut f.step
        else {
            return Ok(());
        };
        while *index < files.len()
            && data[*index].len() as u64 >= files[*index].file_size.unwrap_or(0)
        {
            *index += 1;
        }
        if *index < files.len() {
            let want = files[*index].file_size.unwrap_or(0) - data[*index].len() as u64;
            let req = FileContentsRequest {
                stream_id: *stream,
                index: i32::try_from(*index).unwrap_or(i32::MAX),
                flags: FileContentsFlags::RANGE,
                position: data[*index].len() as u64,
                requested_size: u32::try_from(want).unwrap_or(RANGE).min(RANGE),
                data_id: None,
            };
            f.deadline = Instant::now() + ANSWER;
            return self.send_sender(dir, ClipboardPdu::FileContentsRequest(req));
        }
        // Every byte is in: scan each file on a blocking thread, each under the scan deadline.
        let Step::Contents {
            descriptor,
            files,
            data,
            ..
        } = std::mem::replace(&mut f.step, Step::Descriptor)
        else {
            return Ok(());
        };
        let generation = f.generation;
        f.deadline = Instant::now() + scan_timeout + ANSWER;
        let shared: Vec<Arc<Vec<u8>>> = data.into_iter().map(Arc::new).collect();
        for (index, (file, bytes)) in files.iter().zip(&shared).enumerate() {
            let scanner = Arc::clone(&self.ctx.scanner);
            let name = file.name.clone();
            let bytes = Arc::clone(bytes);
            let back = self.scans.clone();
            let limit = self.ctx.scan_timeout;
            tokio::spawn(async move {
                let job = tokio::task::spawn_blocking(move || scanner.scan(&name, &bytes));
                let verdict = match tokio::time::timeout(limit, job).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => Verdict::Unavailable(format!("the scan failed: {e}")),
                    Err(_) => Verdict::Unavailable("the scan took too long".into()),
                };
                let _ = back
                    .send(Input::Scanned {
                        dir,
                        generation,
                        index,
                        verdict,
                    })
                    .await;
            });
        }
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            return Ok(());
        };
        f.step = Step::Scanning {
            descriptor,
            verdicts: vec![None; files.len()],
            files,
            data: shared
                .into_iter()
                .map(|a| Arc::try_unwrap(a).unwrap_or_else(|a| (*a).clone()))
                .collect(),
        };
        Ok(())
    }

    fn contents(&mut self, dir: Dir, resp: FileContentsResponse<'_>) -> Result<(), ClipError> {
        let fresh = self.next_stream();
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            // Contents the proxy did not ask for go nowhere.
            return Ok(());
        };
        let Step::Contents {
            files,
            data,
            index,
            stream,
            ..
        } = &mut f.step
        else {
            return Ok(());
        };
        if resp.stream_id() != *stream {
            return Ok(());
        }
        if resp.is_error() {
            return self.refuse(dir, "the sender stopped sending a file");
        }
        let size = files[*index].file_size.unwrap_or(0);
        let got = resp.data();
        let room = size - data[*index].len() as u64;
        if got.is_empty() || got.len() as u64 > room.min(u64::from(RANGE)) {
            return self.refuse(dir, "the sender sent a file that does not match its size");
        }
        data[*index].extend_from_slice(got);
        *stream = fresh;
        self.fetch_next(dir)
    }

    fn scanned(
        &mut self,
        dir: Dir,
        generation: u64,
        index: usize,
        verdict: Verdict,
    ) -> Result<(), ClipError> {
        let Phase::Fetching(f) = &mut self.direction(dir).phase else {
            return Ok(());
        };
        if f.generation != generation {
            return Ok(());
        }
        let Step::Scanning { verdicts, .. } = &mut f.step else {
            return Ok(());
        };
        if let Some(slot) = verdicts.get_mut(index) {
            *slot = Some(verdict);
        }
        if verdicts.iter().any(Option::is_none) {
            return Ok(());
        }
        let Phase::Fetching(f) = std::mem::take(&mut self.direction(dir).phase) else {
            return Ok(());
        };
        let Step::Scanning {
            descriptor,
            files,
            data,
            verdicts,
        } = f.step
        else {
            return Ok(());
        };
        let refused: Vec<String> = files
            .iter()
            .zip(&verdicts)
            .filter_map(|(file, v)| match v {
                Some(Verdict::Clean) => None,
                Some(Verdict::Detected) => Some(format!("{}: malware detected", file.name)),
                Some(Verdict::Unavailable(why)) => {
                    Some(format!("{}: not scanned ({why})", file.name))
                }
                None => Some(format!("{}: not scanned", file.name)),
            })
            .collect();
        if !refused.is_empty() {
            (self.ctx.report)(Report::Refused {
                dir,
                files: files_of(&files),
                reason: refused.join("; "),
            });
            return self.clear_receiver(dir);
        }
        (self.ctx.report)(Report::Passed {
            dir,
            files: files_of(&files),
        });
        self.direction(dir).phase = Phase::Offered(Offer {
            file_list: f.file_list,
            descriptor,
            data,
            _reservation: f.reservation,
        });
        // The receiver now gets the sender's own Format List, and answers it to the proxy.
        self.direction(dir).lists_owed.push_back(Owner::Proxy);
        for unit in f.list {
            self.out.push(match dir {
                Dir::Upload => Output::ToServer(unit),
                Dir::Download => Output::ToClient(unit),
            });
        }
        Ok(())
    }

    fn refuse(&mut self, dir: Dir, reason: &str) -> Result<(), ClipError> {
        let files = match &self.direction(dir).phase {
            Phase::Fetching(Fetch {
                step: Step::Contents { files, .. } | Step::Scanning { files, .. },
                ..
            }) => files_of(files),
            _ => Vec::new(),
        };
        (self.ctx.report)(Report::Refused {
            dir,
            files,
            reason: reason.to_owned(),
        });
        self.clear_receiver(dir)
    }

    fn refuse_files(
        &mut self,
        dir: Dir,
        files: &[FileDescriptor],
        reason: &str,
    ) -> Result<(), ClipError> {
        (self.ctx.report)(Report::Refused {
            dir,
            files: files_of(files),
            reason: reason.to_owned(),
        });
        self.clear_receiver(dir)
    }

    /// The receiver is told the clipboard now holds nothing, since the sender's has changed.
    fn clear_receiver(&mut self, dir: Dir) -> Result<(), ClipError> {
        self.direction(dir).phase = Phase::Idle;
        self.direction(dir).lists_owed.push_back(Owner::Proxy);
        let empty = FormatList::new_unicode(&[], self.long_names())
            .map_err(|e| super::route::RouteError::OutOfStep(e.to_string()))?;
        self.send_receiver(dir, ClipboardPdu::FormatList(empty))
    }
}

/// The id of the file-list format, when the list offers one.
fn file_list_format(formats: &[ClipboardFormat]) -> Option<ClipboardFormatId> {
    formats
        .iter()
        .find(|f| f.name().is_some_and(|n| n.value() == FILE_LIST))
        .map(ClipboardFormat::id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::route::tests::{connected, units};
    use crate::scan::route::Routed;
    use ironrdp_cliprdr::pdu::{ClipboardFormatName, ClipboardProtocolVersion, PackedFileList};
    use ironrdp_core::{encode_vec, IntoOwned};

    const FGD: u32 = 0xc0a1;
    const BIG: usize = 2_500_000;

    struct Harness {
        clip: Clip<'static>,
        scans: mpsc::Receiver<Input>,
        reports: Arc<Mutex<Vec<Report>>>,
        staging: Arc<Staging>,
        /// Readers of what the proxy wrote, as each side sees it.
        at_client: Route,
        at_server: Route,
    }

    /// A scanner that finds malware in any file named bad*.
    struct ByName;
    impl Scanner for ByName {
        fn describe(&self) -> String {
            "by name".into()
        }
        fn scan(&self, name: &str, _: &[u8]) -> Verdict {
            if name.starts_with("bad") {
                Verdict::Detected
            } else if name.starts_with("odd") {
                Verdict::Unavailable("no verdict".into())
            } else {
                Verdict::Clean
            }
        }
    }

    fn harness_with(max: Option<u64>, staged: u64, healthy: bool) -> Harness {
        let (tx, rx) = mpsc::channel(64);
        let reports = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&reports);
        let staging = Staging::new(staged);
        let ctx = Context {
            scanner: Arc::new(ByName),
            scan_timeout: Duration::from_secs(5),
            healthy: Arc::new(move || if healthy { Ok(()) } else { Err("down".into()) }),
            max_file_bytes: Arc::new(move || max),
            staging: Arc::clone(&staging),
            report: Arc::new(move |r| sink.lock().unwrap().push(r)),
        };
        Harness {
            clip: Clip::new(ctx, Arc::new(Mutex::new(connected())), tx),
            scans: rx,
            reports,
            staging,
            at_client: connected(),
            at_server: connected(),
        }
    }

    fn harness() -> Harness {
        harness_with(None, 1 << 30, true)
    }

    /// A PDU as the client sends it (Send Data Request units).
    fn from_client(pdu: ClipboardPdu<'static>) -> Whole {
        let r = connected();
        Whole {
            pdu: encode_vec(&pdu).unwrap(),
            units: units(&r.to_server(pdu).unwrap(), false),
        }
    }

    /// A PDU as the server sends it (Send Data Indication units).
    fn from_server(pdu: ClipboardPdu<'static>) -> Whole {
        let r = connected();
        Whole {
            pdu: encode_vec(&pdu).unwrap(),
            units: units(&r.to_client(pdu).unwrap(), true),
        }
    }

    enum Seen {
        Client(Vec<u8>),
        Server(Vec<u8>),
    }

    impl Harness {
        /// What the proxy wrote since the last call, decoded as each side would read it.
        fn written(&mut self) -> Vec<Seen> {
            let mut seen = Vec::new();
            for o in std::mem::take(&mut self.clip.out) {
                let (bytes, to_client) = match o {
                    Output::ToClient(b) => (b, true),
                    Output::ToServer(b) => (b, false),
                };
                for u in units(&bytes, to_client) {
                    let routed = if to_client {
                        self.at_client.read_server(&u)
                    } else {
                        self.at_server.read_client(&u)
                    };
                    if let Routed::Clip(Some(w)) = routed.unwrap() {
                        seen.push(if to_client {
                            Seen::Client(w.pdu)
                        } else {
                            Seen::Server(w.pdu)
                        });
                    }
                }
            }
            seen
        }

        fn client(&mut self, pdu: ClipboardPdu<'static>) {
            self.clip
                .handle(Input::FromClient(from_client(pdu)))
                .unwrap();
        }

        fn server(&mut self, pdu: ClipboardPdu<'static>) {
            self.clip
                .handle(Input::FromServer(from_server(pdu)))
                .unwrap();
        }

        async fn verdicts(&mut self, n: usize) {
            for _ in 0..n {
                let v = self.scans.recv().await.unwrap();
                self.clip.handle(v).unwrap();
            }
        }
    }

    fn decoded(bytes: &[u8]) -> ClipboardPdu<'_> {
        ironrdp_core::decode::<ClipboardPdu<'_>>(bytes).unwrap()
    }

    fn file_offer() -> ClipboardPdu<'static> {
        let formats = [
            ClipboardFormat::new(ClipboardFormatId::new(FGD))
                .with_name(ClipboardFormatName::new(FILE_LIST)),
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ];
        ClipboardPdu::FormatList(FormatList::new_unicode(&formats, true).unwrap())
    }

    fn descriptors(files: &[(&str, usize)]) -> ClipboardPdu<'static> {
        let list = PackedFileList {
            files: files
                .iter()
                .map(|(n, s)| FileDescriptor::new(*n).with_file_size(*s as u64))
                .collect(),
        };
        ClipboardPdu::FormatDataResponse(
            FormatDataResponse::new_file_list(&list)
                .unwrap()
                .into_owned(),
        )
    }

    fn content(i: usize) -> Vec<u8> {
        (0..BIG).map(|n| (n % 251) as u8 ^ i as u8).collect()
    }

    /// Answers every range request the proxy makes of the client until none is left.
    fn serve_ranges(h: &mut Harness, files: &[Vec<u8>]) -> usize {
        let mut asked = 0;
        loop {
            let mut next = None;
            for s in h.written() {
                match s {
                    Seen::Client(b) => {
                        if let ClipboardPdu::FileContentsRequest(r) = decoded(&b) {
                            next = Some(r);
                        }
                    }
                    Seen::Server(_) => panic!("the server was written to before the scan"),
                }
            }
            let Some(r) = next else {
                return asked;
            };
            asked += 1;
            let f = &files[r.index as usize];
            let start = r.position as usize;
            let end = (start + r.requested_size as usize).min(f.len());
            h.client(ClipboardPdu::FileContentsResponse(
                FileContentsResponse::new_data_response(r.stream_id, f[start..end].to_vec()),
            ));
        }
    }

    #[tokio::test]
    async fn an_upload_reaches_the_server_only_once_every_file_has_scanned_clean() {
        let mut h = harness();
        let offer = from_client(file_offer());
        h.clip.handle(Input::FromClient(offer.clone())).unwrap();
        let first: Vec<ClipboardPdu<'_>> = Vec::new();
        drop(first);
        let seen = h.written();
        let mut asked_list = false;
        for s in &seen {
            match s {
                Seen::Client(b) => match decoded(b) {
                    ClipboardPdu::FormatListResponse(FormatListResponse::Ok) => {}
                    ClipboardPdu::FormatDataRequest(r) => {
                        assert_eq!(r.format, ClipboardFormatId::new(FGD));
                        asked_list = true;
                    }
                    other => panic!("unexpected {}", other.message_name()),
                },
                Seen::Server(_) => panic!("the offer reached the server unscanned"),
            }
        }
        assert!(asked_list);

        h.client(descriptors(&[("notes.txt", 5), ("data.bin", BIG)]));
        let files = vec![b"hello".to_vec(), content(1)];
        let asked = serve_ranges(&mut h, &files);
        assert_eq!(asked, 1 + BIG.div_ceil(RANGE as usize), "one range per MiB");
        h.verdicts(2).await;

        // Now, and only now, the server gets the client's own Format List, byte for byte.
        let outs = std::mem::take(&mut h.clip.out);
        let to_server: Vec<Vec<u8>> = outs
            .into_iter()
            .filter_map(|o| match o {
                Output::ToServer(b) => Some(b),
                Output::ToClient(_) => None,
            })
            .collect();
        assert_eq!(to_server, offer.units);
        assert!(matches!(
            h.reports.lock().unwrap().last(),
            Some(Report::Passed {
                dir: Dir::Upload,
                ..
            })
        ));

        // The server's answers and requests are served from the scanned copy.
        h.server(ClipboardPdu::FormatListResponse(FormatListResponse::Ok));
        assert!(
            h.written().is_empty(),
            "the server's list response is the proxy's"
        );
        h.server(ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::new(FGD),
        }));
        let [Seen::Server(b)] = &h.written()[..] else {
            panic!("no descriptor answer");
        };
        let ClipboardPdu::FormatDataResponse(d) = decoded(b) else {
            panic!()
        };
        assert_eq!(d.to_file_list().unwrap().files.len(), 2);
        h.server(ClipboardPdu::FileContentsRequest(FileContentsRequest {
            stream_id: 77,
            index: 1,
            flags: FileContentsFlags::RANGE,
            position: 1_000_000,
            requested_size: 1000,
            data_id: None,
        }));
        let [Seen::Server(b)] = &h.written()[..] else {
            panic!("no contents answer");
        };
        let ClipboardPdu::FileContentsResponse(c) = decoded(b) else {
            panic!()
        };
        assert_eq!(c.stream_id(), 77);
        assert_eq!(c.data(), &files[1][1_000_000..1_001_000]);
    }

    #[tokio::test]
    async fn an_upload_holding_malware_is_refused_whole_and_the_server_gets_an_empty_clipboard() {
        let mut h = harness();
        h.client(file_offer());
        h.written();
        h.client(descriptors(&[("fine.txt", 4), ("bad.exe", 4)]));
        serve_ranges(&mut h, &[b"fine".to_vec(), b"evil".to_vec()]);
        h.verdicts(2).await;
        let seen = h.written();
        assert_eq!(seen.len(), 1);
        let Seen::Server(b) = &seen[0] else { panic!() };
        let ClipboardPdu::FormatList(l) = decoded(b) else {
            panic!("the server was not given an empty clipboard")
        };
        assert!(l.get_formats(true).unwrap().is_empty());
        let reports = h.reports.lock().unwrap();
        let Some(Report::Refused { reason, files, .. }) = reports.last() else {
            panic!()
        };
        assert!(reason.contains("bad.exe: malware detected"), "{reason}");
        assert_eq!(files.len(), 2);
        drop(reports);
        // A contents request for the refused offer gets nothing.
        h.server(ClipboardPdu::FileContentsRequest(FileContentsRequest {
            stream_id: 5,
            index: 0,
            flags: FileContentsFlags::RANGE,
            position: 0,
            requested_size: 4,
            data_id: None,
        }));
        let [Seen::Server(b)] = &h.written()[..] else {
            panic!()
        };
        let ClipboardPdu::FileContentsResponse(c) = decoded(b) else {
            panic!()
        };
        assert!(c.is_error());
        assert_eq!(h.staging.held(), 0, "the refused files' room is released");
    }

    #[tokio::test]
    async fn a_file_the_scanner_gives_no_verdict_for_is_refused() {
        let mut h = harness();
        h.client(file_offer());
        h.written();
        h.client(descriptors(&[("fine.txt", 4), ("odd.bin", 4)]));
        serve_ranges(&mut h, &[b"fine".to_vec(), b"what".to_vec()]);
        h.verdicts(2).await;
        let seen = h.written();
        let [Seen::Server(b)] = &seen[..] else {
            panic!("the server was not told the clipboard is empty")
        };
        let ClipboardPdu::FormatList(l) = decoded(b) else {
            panic!()
        };
        assert!(l.get_formats(true).unwrap().is_empty());
        let reports = h.reports.lock().unwrap();
        let Some(Report::Refused { reason, .. }) = reports.last() else {
            panic!("not refused")
        };
        assert!(
            reason.contains("odd.bin: not scanned (no verdict)"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn a_new_clipboard_mid_scan_replaces_the_offer_and_late_verdicts_count_for_nothing() {
        let mut h = harness();
        h.client(file_offer());
        h.written();
        h.client(descriptors(&[("a.txt", 3)]));
        serve_ranges(&mut h, &[b"abc".to_vec()]);
        // Text replaces the files before the verdict comes back.
        let text = ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)],
                true,
            )
            .unwrap(),
        );
        h.client(text);
        assert!(
            matches!(&h.written()[..], [Seen::Server(_)]),
            "text passes through"
        );
        h.verdicts(1).await;
        assert!(h.written().is_empty(), "a stale verdict offers nothing");
        assert_eq!(h.staging.held(), 0);
    }

    #[tokio::test]
    async fn a_verdict_for_a_replaced_offer_never_decides_the_new_one() {
        let mut h = harness();
        h.client(file_offer());
        h.written();
        h.client(descriptors(&[("bad.exe", 4)]));
        serve_ranges(&mut h, &[b"evil".to_vec()]);
        // A second offer replaces the first while its scan is out, and reaches a scan of its own.
        h.client(file_offer());
        h.written();
        h.client(descriptors(&[("fine.txt", 4)]));
        serve_ranges(&mut h, &[b"fine".to_vec()]);
        let mut late = vec![h.scans.recv().await.unwrap(), h.scans.recv().await.unwrap()];
        // The replaced offer's verdict arrives first.
        late.sort_by_key(|i| match i {
            Input::Scanned { generation, .. } => *generation,
            _ => u64::MAX,
        });
        for i in late {
            h.clip.handle(i).unwrap();
        }
        let reports = h.reports.lock().unwrap();
        assert!(
            matches!(reports.last(), Some(Report::Passed { files, .. }) if files[0].0 == "fine.txt"),
            "{:?}",
            reports.last()
        );
    }

    #[test]
    fn text_passes_both_ways_and_locks_are_masked_out() {
        let mut h = harness();
        let caps = Capabilities::new(
            ClipboardProtocolVersion::V2,
            ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA,
        );
        h.server(ClipboardPdu::Capabilities(caps));
        let [Seen::Client(b)] = &h.written()[..] else {
            panic!()
        };
        let ClipboardPdu::Capabilities(c) = decoded(b) else {
            panic!()
        };
        assert!(!c
            .flags()
            .contains(ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA));
        assert!(c
            .flags()
            .contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));

        let text = from_client(ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)],
                true,
            )
            .unwrap(),
        ));
        h.clip.handle(Input::FromClient(text.clone())).unwrap();
        let outs: Vec<Vec<u8>> = std::mem::take(&mut h.clip.out)
            .into_iter()
            .map(|o| match o {
                Output::ToServer(b) => b,
                Output::ToClient(_) => panic!("text went back to the client"),
            })
            .collect();
        assert_eq!(outs, text.units, "text passes byte for byte");
        // The server's answer and its request pass back; the client's data passes forward.
        h.server(ClipboardPdu::FormatListResponse(FormatListResponse::Ok));
        assert!(matches!(&h.written()[..], [Seen::Client(_)]));
        h.server(ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        }));
        assert!(matches!(&h.written()[..], [Seen::Client(_)]));
        h.client(ClipboardPdu::FormatDataResponse(
            FormatDataResponse::new_unicode_string("hi"),
        ));
        let [Seen::Server(b)] = &h.written()[..] else {
            panic!()
        };
        let ClipboardPdu::FormatDataResponse(d) = decoded(b) else {
            panic!()
        };
        assert_eq!(d.to_unicode_string().unwrap(), "hi");
    }

    fn refused_with(h: &mut Harness, files: &[(&str, usize)], want: &str) {
        h.client(file_offer());
        h.written();
        let list = PackedFileList {
            files: files
                .iter()
                .map(|(n, s)| {
                    let d = FileDescriptor::new(*n).with_file_size(*s as u64);
                    if n.ends_with('/') {
                        d.with_attributes(ClipboardFileAttributes::DIRECTORY)
                    } else {
                        d
                    }
                })
                .collect(),
        };
        h.client(ClipboardPdu::FormatDataResponse(
            FormatDataResponse::new_file_list(&list)
                .unwrap()
                .into_owned(),
        ));
        let seen = h.written();
        assert!(
            seen.iter().all(|s| matches!(s, Seen::Server(_))),
            "no file bytes were asked for"
        );
        let reports = h.reports.lock().unwrap();
        let Some(Report::Refused { reason, .. }) = reports.last() else {
            panic!("not refused")
        };
        assert!(reason.contains(want), "{reason}");
    }

    #[test]
    fn folders_oversized_files_and_too_much_at_once_are_refused_before_any_byte_moves() {
        refused_with(&mut harness(), &[("docs/", 0)], "folders");
        refused_with(
            &mut harness_with(Some(10), 1 << 30, true),
            &[("a.bin", 11)],
            "file-size limit",
        );
        refused_with(
            &mut harness_with(None, 100, true),
            &[("a.bin", 60), ("b.bin", 60)],
            "at once",
        );
    }

    #[test]
    fn a_scanner_that_is_not_answering_refuses_every_offer() {
        let mut h = harness_with(None, 1 << 30, false);
        h.client(file_offer());
        let seen = h.written();
        assert!(
            seen.iter().any(|s| matches!(s, Seen::Server(_))),
            "the server's clipboard is cleared"
        );
        assert!(!seen.iter().any(|s| matches!(s, Seen::Client(b) if matches!(decoded(b), ClipboardPdu::FormatDataRequest(_)))));
        assert!(matches!(
            h.reports.lock().unwrap().last(),
            Some(Report::Refused { reason, .. }) if reason.contains("not answering")
        ));
    }

    #[tokio::test]
    async fn a_download_is_held_and_scanned_the_same_way() {
        let mut h = harness();
        let offer = from_server(file_offer());
        h.clip.handle(Input::FromServer(offer.clone())).unwrap();
        assert!(h.written().iter().all(|s| matches!(s, Seen::Server(_))));
        h.server(descriptors(&[("report.pdf", 6)]));
        let mut asked = None;
        for s in h.written() {
            match s {
                Seen::Server(b) => {
                    if let ClipboardPdu::FileContentsRequest(r) = decoded(&b) {
                        asked = Some(r);
                    }
                }
                Seen::Client(_) => panic!("the client was written to before the scan"),
            }
        }
        let r = asked.unwrap();
        h.server(ClipboardPdu::FileContentsResponse(
            FileContentsResponse::new_data_response(r.stream_id, b"report".to_vec()),
        ));
        h.verdicts(1).await;
        let to_client: Vec<Vec<u8>> = std::mem::take(&mut h.clip.out)
            .into_iter()
            .filter_map(|o| match o {
                Output::ToClient(b) => Some(b),
                Output::ToServer(_) => None,
            })
            .collect();
        assert_eq!(to_client, offer.units);
    }

    #[tokio::test]
    async fn a_sender_that_stops_answering_is_refused() {
        let mut h = harness();
        h.client(file_offer());
        h.written();
        h.clip
            .expire_at(Instant::now() + ANSWER - Duration::from_secs(1))
            .unwrap();
        assert!(
            h.reports.lock().unwrap().is_empty(),
            "refused before its time"
        );
        h.clip
            .expire_at(Instant::now() + ANSWER + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            h.reports.lock().unwrap().last(),
            Some(Report::Refused { reason, .. }) if reason.contains("too long")
        ));
    }
}
