//! An independent I2C-medium model checks arbitrary interrupted-byte values.
//! This is a host fault model, not evidence of electrical brownout behavior.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{cell::RefCell, rc::Rc};

use embedded_hal::i2c::{ErrorKind, ErrorType, I2c, Operation};
use genesismesh_radio_device::device::{Storage, STATE_BYTES};
use genesismesh_radio_wisblock::fram::{Fram, FramJournal, JOURNAL_BYTES, SLOT_BYTES};

struct Medium {
    bytes: [u8; JOURNAL_BYTES],
    /// Fail while writing this data-byte index, after leaving an arbitrary value.
    torn: Option<(usize, u8)>,
    data_writes: usize,
    /// Fail at an I2C transaction boundary, either before or after its effects.
    transaction_fault: Option<(usize, bool)>,
    transactions: usize,
}

impl Medium {
    fn blank() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            bytes: [0xff; JOURNAL_BYTES],
            torn: None,
            data_writes: 0,
            transaction_fault: None,
            transactions: 0,
        }))
    }
}

#[derive(Clone)]
struct Bus(Rc<RefCell<Medium>>);

impl ErrorType for Bus {
    type Error = ErrorKind;
}

impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), ErrorKind> {
        assert_eq!(address, 0x56);
        let mut medium = self.0.borrow_mut();
        let transaction = medium.transactions;
        medium.transactions += 1;
        if medium.transaction_fault == Some((transaction, false)) {
            return Err(ErrorKind::Other);
        }
        let mut pointer = 0;
        for operation in operations {
            match operation {
                Operation::Write(data) => {
                    assert!((2..=18).contains(&data.len()));
                    pointer = usize::from(u16::from_be_bytes([data[0], data[1]]));
                    for &byte in &data[2..] {
                        if let Some((at, unknown)) = medium.torn {
                            if at == medium.data_writes {
                                medium.bytes[pointer] = unknown;
                                return Err(ErrorKind::Other);
                            }
                        }
                        medium.bytes[pointer] = byte;
                        pointer += 1;
                        medium.data_writes += 1;
                    }
                }
                Operation::Read(data) => {
                    assert!(data.len() <= 16);
                    data.copy_from_slice(&medium.bytes[pointer..pointer + data.len()]);
                    pointer += data.len();
                }
            }
        }
        if medium.transaction_fault == Some((transaction, true)) {
            return Err(ErrorKind::Other);
        }
        Ok(())
    }
}

fn store(medium: &Rc<RefCell<Medium>>) -> FramJournal<Bus> {
    FramJournal::new(Fram::new(Bus(Rc::clone(medium))), 0).unwrap()
}

#[test]
fn every_possible_torn_byte_refuses_intermediate_journal_recovery() {
    for previous in 0..=3u8 {
        let medium = Medium::blank();
        for generation in 1..=previous {
            store(&medium).commit(&[generation; STATE_BYTES]).unwrap();
        }
        let baseline = medium.borrow().bytes;
        // In addition to slot bytes, update the commit marker and, after the
        // initial generation, retire the old current marker.
        let total = SLOT_BYTES + 1 + usize::from(previous != 0);
        for at in 0..total {
            for unknown in 0..=255u8 {
                {
                    let mut state = medium.borrow_mut();
                    state.bytes = baseline;
                    state.data_writes = 0;
                    state.torn = Some((at, unknown));
                }
                // An arbitrary value equal to the final intended byte also
                // models that byte persisting while its ACK is lost.
                assert!(store(&medium).commit(&[9; STATE_BYTES]).is_err());
                medium.borrow_mut().torn = None;
                if let Ok(value) = store(&medium).load() {
                    if at == 0 {
                        assert_eq!(value, (previous != 0).then_some([previous; STATE_BYTES]));
                    } else {
                        assert_eq!(at, total - 1, "accepted cut before final marker");
                        assert_eq!(unknown, 0xa5, "accepted unknown final marker");
                        assert_eq!(value, Some([9; STATE_BYTES]));
                    }
                }
            }
        }
    }
}

#[test]
fn every_transaction_failure_before_or_after_effects_is_old_new_or_refused() {
    for previous in 0..=3u8 {
        let medium = Medium::blank();
        for generation in 1..=previous {
            store(&medium).commit(&[generation; STATE_BYTES]).unwrap();
        }
        let baseline = medium.borrow().bytes;
        medium.borrow_mut().transactions = 0;
        store(&medium).commit(&[9; STATE_BYTES]).unwrap();
        let total = medium.borrow().transactions;
        for at in 0..total {
            for after_effects in [false, true] {
                {
                    let mut state = medium.borrow_mut();
                    state.bytes = baseline;
                    state.transactions = 0;
                    state.transaction_fault = Some((at, after_effects));
                }
                assert!(store(&medium).commit(&[9; STATE_BYTES]).is_err());
                medium.borrow_mut().transaction_fault = None;
                if let Ok(value) = store(&medium).load() {
                    assert!(
                        value == Some([9; STATE_BYTES])
                            || value == (previous != 0).then_some([previous; STATE_BYTES]),
                        "a failed operation must not invent a snapshot"
                    );
                }
            }
        }
    }
}
