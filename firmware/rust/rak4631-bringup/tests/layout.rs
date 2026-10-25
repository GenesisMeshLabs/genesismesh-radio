use rak4631_bringup::{FLASH_LENGTH, FLASH_ORIGIN, RAM_LENGTH, RAM_ORIGIN};

#[test]
fn manifest_and_linker_constants_retain_vendor_reserved_ranges(
) -> Result<(), Box<dyn std::error::Error>> {
    let layout: serde_json::Value = serde_json::from_str(include_str!("../memory-layout.json"))?;
    assert_eq!(layout["board"], "RAK4631");
    assert_eq!(layout["flash_origin"], FLASH_ORIGIN);
    assert_eq!(layout["flash_length"], FLASH_LENGTH);
    assert_eq!(layout["ram_origin"], RAM_ORIGIN);
    assert_eq!(layout["ram_length"], RAM_LENGTH);
    assert_eq!(FLASH_ORIGIN, 0x26000);
    assert_eq!(FLASH_ORIGIN + FLASH_LENGTH, 0xed000);
    assert_eq!(RAM_ORIGIN, 0x20006000);
    assert_eq!(RAM_ORIGIN + RAM_LENGTH, 0x20040000);
    assert_eq!(layout["radio_transmission"], false);
    assert_eq!(layout["hardware_tested"], false);
    Ok(())
}
