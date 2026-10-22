#![no_main]
//! Schemas arrive from other members via the catalogue and instances from
//! anyone. Compiling and checking must not panic, and must finish quickly.
use libfuzzer_sys::fuzz_target;
use zroad_core::schema::CompiledSchema;

fuzz_target!(|data: &[u8]| {
    // first byte (as a fraction of the rest) splits the input into schema and instance
    let Some((&split, rest)) = data.split_first() else { return };
    let at = rest.len() * split as usize / 256;
    let (schema, instance) = rest.split_at(at);
    let Ok(schema) = serde_json::from_slice::<serde_json::Value>(schema) else { return };
    let Ok(compiled) = CompiledSchema::compile(&schema) else { return };
    let _ = compiled.check_bytes(instance);
});
