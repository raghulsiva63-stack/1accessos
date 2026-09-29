//! Locks the vault when the computer sleeps or the screen locks.
//!
//! A background thread checks every two seconds:
//! * sleep/hibernate: the wall clock jumped far past the expected tick (all systems);
//! * screen lock: Windows (input desktop unavailable) and macOS (session reports the screen as locked).
//!   Linux relies on the sleep check and the idle timeout.

use std::time::{Duration, SystemTime};

const TICK: Duration = Duration::from_secs(2);
const SLEEP_GAP: Duration = Duration::from_secs(20);

/// True when more wall-clock time passed than a normal tick allows (the machine was asleep).
pub fn slept(previous: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(previous) {
        Ok(elapsed) => elapsed > TICK + SLEEP_GAP,
        Err(_) => true, // clock went backwards: lock to be safe
    }
}

pub fn watch(on_lock: impl Fn(&'static str) + Send + 'static) {
    std::thread::Builder::new()
        .name("passkey-x-lock-guard".into())
        .spawn(move || {
            let mut previous = SystemTime::now();
            let mut was_locked = false;
            loop {
                std::thread::sleep(TICK);
                let now = SystemTime::now();
                if slept(previous, now) {
                    on_lock("sleep");
                }
                previous = now;
                let locked = screen_locked();
                if locked && !was_locked {
                    on_lock("screen-lock");
                }
                was_locked = locked;
            }
        })
        .ok();
}

#[cfg(target_os = "windows")]
fn screen_locked() -> bool {
    use windows::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP};
    // While the workstation is locked the input desktop is the secure Winlogon desktop,
    // which a normal process cannot open.
    match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP) } {
        Ok(desktop) => {
            let _ = unsafe { CloseDesktop(desktop) };
            false
        }
        Err(_) => true,
    }
}

#[cfg(target_os = "macos")]
fn screen_locked() -> bool {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }
    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return false;
    }
    let dictionary: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    dictionary
        .find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|value| value.downcast::<CFBoolean>())
        .map(bool::from)
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn screen_locked() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sleep_and_clock_rollback() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(!slept(start, start + Duration::from_secs(3)));
        assert!(slept(start, start + Duration::from_secs(120)));
        assert!(slept(start, start - Duration::from_secs(1)));
    }
}
