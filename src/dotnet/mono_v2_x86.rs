use super::{CStr, MonoPtr32};
use crate::{Address, Address32, Error, Process};
use bytemuck::{Pod, Zeroable};
use core::{iter, marker::PhantomData, mem};

pub struct MonoModule<'a> {
    process: &'a Process,
    assemblies: MonoPtr32<MonoPtr32<GList>>,
}

impl<'a> MonoModule<'a> {
    pub fn attach(process: &'a Process) -> Option<Self> {
        let mono_module = process.get_module_address("mono-2.0-bdwgc.dll").ok()?;
        let mono_offsets = super::MonoPEOffsets::new(false);

        // Get root domain address: code essentially stolen from UnitySpy -
        // See https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/AssemblyImageFactory.cs#L123
        let start_index = process
            .read::<u32>(mono_module + mono_offsets.signature)
            .ok()? as u64;

        let export_directory_index = start_index + mono_offsets.export_directory_index_pe as u64;

        let export_directory = process
            .read::<u32>(mono_module + export_directory_index)
            .ok()? as u64;

        let number_of_functions = process
            .read::<u32>(mono_module + export_directory + mono_offsets.number_of_functions)
            .ok()?;
        let function_address_array_index = process
            .read::<u32>(mono_module + export_directory + mono_offsets.function_address_array_index)
            .ok()?;
        let function_name_array_index = process
            .read::<u32>(mono_module + export_directory + mono_offsets.function_name_array_index)
            .ok()?;

        let mut root_domain_function_address = Address::NULL;

        for val in 0..number_of_functions {
            let function_name_index = process
                .read::<u32>(mono_module + function_name_array_index + val * 4)
                .ok()?;
            let function_name = process
                .read::<[u8; 21]>(mono_module + function_name_index)
                .ok()?;

            if &function_name == b"mono_assembly_foreach" {
                root_domain_function_address = mono_module
                    + process
                        .read::<u32>(mono_module + function_address_array_index + val * 4)
                        .ok()?;
                break;
            }
        }
        if root_domain_function_address == Address::NULL {
            return None;
        }

        let scan_address: Address = if let Some(x) = super::SIG_MONO_32_1.scan_process_range(process, (root_domain_function_address, 0x100)) {
            x + 2
        } else if let Some(y) = super::SIG_MONO_32_2.scan_process_range(process, (root_domain_function_address, 0x100)) {
            y + 2 
        } else {
            return None;
        };

        let assemblies = MonoPtr32(
            Address32::new(
                process.read::<Address32>(scan_address).ok()?.value(),
            ),
            PhantomData::<MonoPtr32<GList>>,
        );

        Some(Self {
            process,
            assemblies,
        })
    }

    pub fn get_image(&self, assembly_name: &str) -> Option<MonoImageContainer<'_>> {
        let mut assemblies = self
            .assemblies
            .read(self.process)
            .ok()?
            .read(self.process)
            .ok()?;
        crate::print_message("text");

        let image = loop {
            if assemblies.data.is_null() {
                return None;
            }

            let ptr = assemblies
                .data
                .read(self.process)
                .ok()?;

            let name = ptr.aname.name.read_str::<128>(self.process).ok()?;
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];

            if name == assembly_name.as_bytes() {
                break ptr.image.read(self.process).ok()?;
            }

            assemblies = assemblies.next.read(self.process).ok()?;
        };

        Some(MonoImageContainer {
            mono_module: self,
            mono_image: image,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct GList {
    data: MonoPtr32<MonoAssembly>,
    next: MonoPtr32<GList>,
    prev: MonoPtr32<GList>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssembly {
    ref_count: i32,
    basedir: MonoPtr32<CStr>,
    aname: MonoAssemblyName,
    image: MonoPtr32<MonoImage>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssemblyName {
    name: MonoPtr32<CStr>,
    culture: MonoPtr32<CStr>,
    hash_value: MonoPtr32<CStr>,
    public_key: MonoPtr32,
    public_key_token: [u8; 17],
    _padding1: [u8; 3],
    hash_alg: u32,
    hash_len: u32,
    flags: u32,
    major: u16,
    minor: u16,
    build: u16,
    revision: u16,
    arch: u16,
    _padding: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoImage {
    ref_count: i32,
    raw_data_handle: MonoPtr32,
    raw_data: MonoPtr32<u8>,
    raw_data_len: u32,
    various_flags: [u8; 2],
    _padding0: [u8; 2],
    name: MonoPtr32<CStr>,
    assembly_name: MonoPtr32<CStr>,
    module_name: MonoPtr32<CStr>,
    version: MonoPtr32<CStr>,
    md_version_major: i16,
    md_version_minor: i16,
    guid: MonoPtr32<CStr>,
    image_info: MonoPtr32, // MonoCLIImageInfo
    mempool: MonoPtr32,    // MonoMemPool
    raw_metadata: MonoPtr32<u8>,
    heap_strings: MonoStreamHeader,
    heap_us: MonoStreamHeader,
    heap_blob: MonoStreamHeader,
    heap_guid: MonoStreamHeader,
    heap_tables: MonoStreamHeader,
    heap_pdb: MonoStreamHeader,
    tables_base: MonoPtr32<u8>,
    referenced_tables: u32,
    referenced_tables_1: u32,
    referenced_table_rows: MonoPtr32<i32>,
    tables: [MonoTableInfo; 56],
    references: MonoPtr32<MonoPtr32<MonoAssembly>>,
    nreferences: i32,
    modules: MonoPtr32<MonoPtr32<MonoImage>>,
    module_count: u32,
    modules_loaded: MonoPtr32<u8>,
    files: MonoPtr32<MonoPtr32<MonoImage>>,
    file_count: u32,
    aot_module: MonoPtr32, // MonoAotModule
    aotid: [u8; 16],
    assembly: MonoPtr32<MonoAssembly>,
    method_cache: MonoPtr32, // GHashTable
    class_cache: MonoInternalHashTable,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoStreamHeader {
    data: MonoPtr32<u8>,
    size: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoTableInfo {
    base: MonoPtr32<u8>,
    rows_and_size: u32,
    size_bitfield: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoInternalHashTable {
    hash_func: MonoPtr32<u32>,
    key_extract: MonoPtr32,
    next_value: MonoPtr32,
    size: i32,
    num_entries: i32,
    table: MonoPtr32<MonoPtr32<MonoClassDef>>,
}

pub struct MonoImageContainer<'a> {
    mono_module: &'a MonoModule<'a>,
    mono_image: MonoImage,
}

impl MonoImageContainer<'_> {
    fn classes(&self) -> Result<impl Iterator<Item = MonoClassDef> + '_, Error> {
        let ptr = (0..self.mono_image.class_cache.size as usize).flat_map(move |i| {
            let mut table = self
                .mono_image
                .class_cache
                .table
                .index(self.mono_module.process, i)
                .unwrap_or(MonoPtr32(Address32::NULL, PhantomData));
            iter::from_fn(move || {
                if !table.is_null() {
                    let class = table.read(self.mono_module.process).ok()?;
                    table = class.next_class_cache;
                    Some(class)
                } else {
                    None
                }
            })
        });

        Ok(ptr)
    }

    pub fn get_class(&self, class_name: &str) -> Option<MonoClassContainer<'_>> {
        let mut classes = self.classes().ok()?;
        classes
            .find(|c| {
                if let Ok(success) = c.klass.name.read_str::<128>(self.mono_module.process) {
                    let success = &success[..success
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(success.len())];
                    success == class_name.as_bytes() && !c.klass.fields.is_null()
                } else {
                    false
                }
            })
            .map(|m| MonoClassContainer {
                mono_module: self.mono_module,
                mono_class: m,
            })
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoClassDef {
    klass: MonoClass,
    flags: u32,
    first_method_idx: u32,
    first_field_idx: u32,
    method_count: u32,
    field_count: u32,
    next_class_cache: MonoPtr32<MonoClassDef>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClass {
    element_class: MonoPtr32<MonoClass>,
    cast_class: MonoPtr32<MonoClass>,
    supertypes: MonoPtr32<MonoPtr32<MonoClass>>,
    idepth: u16,
    rank: u8,
    _padding: u8,
    instance_size: i32,
    flags1: u32,
    min_align: u8,
    _padding2: [u8; 3],
    flags2: u32,
    parent: MonoPtr32<MonoClassDef>, // MonoClass
    nested_in: MonoPtr32<MonoClass>,
    image: MonoPtr32<MonoImage>,
    name: MonoPtr32<CStr>,
    name_space: MonoPtr32<CStr>,
    type_token: u32,
    vtable_size: i32,
    interface_count: u16,
    _padding4: [u8; 2],
    interface_id: u32,
    max_interface_id: u32,
    interface_offset_count: u16,
    _padding5: [u8; 2],
    interfaces_packed: MonoPtr32<MonoPtr32<MonoClass>>,
    interface_offsets_packed: MonoPtr32<u16>,
    interface_bitmap: MonoPtr32<u8>,
    interfaces: MonoPtr32<MonoPtr32<MonoClass>>,
    sizes: i32,
    fields: MonoPtr32<MonoClassField>,
    methods: MonoPtr32<MonoPtr32>, // MonoMethod
    this_arg: MonoType,
    byval_arg: MonoType,
    gc_descr: MonoPtr32,
    runtime_info: MonoPtr32<MonoClassRuntimeInfo>, // MonoClassRuntimeInfo
    vtable: MonoPtr32<MonoPtr32>,                  // MonoMethod
    infrequent_data: MonoPtr32,                    // MonoPropertyBag
    user_data: MonoPtr32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoClassRuntimeInfo {
    max_domain: u16,
    _padding: [u8; 2],
    domain_vtables: MonoPtr32<MonoVTable>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoVTable {
    klass: MonoPtr32<MonoClass>,
    gc_descr: MonoPtr32, // MonoGCDescriptor = sizeof(Ptr)
    domain: MonoPtr32,   // MonoDomain
    r#type: MonoPtr32,
    interface_bitmap: MonoPtr32<u8>,
    max_interface_id: u32,
    rank: u8,
    initialized: u8,
    _padding1: [u8; 2],
    flags: u32,
    imt_collisions_bitmap: u32,
    runtime_generic_context: MonoPtr32,
    vtable: MonoPtr32,
}

pub struct MonoClassContainer<'a> {
    mono_module: &'a MonoModule<'a>,
    mono_class: MonoClassDef,
}

impl MonoClassContainer<'_> {
    fn fields(&self) -> impl Iterator<Item = MonoClassField> + '_ {
        (0..self.mono_class.field_count as usize).flat_map(|i| {
            self.mono_class
                .klass
                .fields
                .index(self.mono_module.process, i)
        })
    }

    pub fn get_field(&self, name: &str) -> Option<u64> {
        Some(
            self.fields()
                .find(|field| {
                    let success = field
                        .name
                        .read_str::<128>(self.mono_module.process)
                        .unwrap_or([0; 128]);
                    let success = &success[..success
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(success.len())];
                    success == name.as_bytes()
                })?
                .offset as _,
        )
    }

    pub fn get_static_table(&self) -> Option<Address> {
        let addr = self
            .mono_class
            .klass
            .runtime_info
            .read(self.mono_module.process)
            .ok()?
            .domain_vtables
            .byte_offset(mem::size_of::<MonoVTable>() as u32 - mem::size_of::<MonoPtr32>() as u32) // hack
            .cast::<MonoPtr32>()
            .index(
                self.mono_module.process,
                self.mono_class.klass.vtable_size as usize,
            )
            .ok()?
            .get();

        if addr.is_null() {
            None
        } else {
            Some(addr)
        }
    }

    pub fn get_parent(&self) -> Option<MonoClassContainer<'_>> {
        let parent = self
            .mono_class
            .klass
            .parent
            .read(self.mono_module.process)
            .ok()?;
        Some(MonoClassContainer {
            mono_module: self.mono_module,
            mono_class: parent,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoType {
    data: MonoPtr32,
    attrs: u16,
    r#type: u8,
    flags: u8,
    modifiers: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClassField {
    r#type: MonoPtr32<MonoType>,
    name: MonoPtr32<CStr>,
    parent: MonoPtr32<MonoClass>,
    offset: i32,
}
