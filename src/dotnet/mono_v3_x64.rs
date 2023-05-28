use super::{CStr, MonoPtr64};
use crate::{Address, Address64, Error, Process};
use bytemuck::{Pod, Zeroable};
use core::{iter, marker::PhantomData, mem};

pub struct MonoModule<'a> {
    process: &'a Process,
    assemblies: MonoPtr64<MonoPtr64<GList>>,
}

impl<'a> MonoModule<'a> {
    pub fn attach(process: &'a Process) -> Option<Self> {
        let mono_module = process.get_module_address("mono-2.0-bdwgc.dll").ok()?;
        let mono_offsets = super::MonoPEOffsets::new(true);

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

        let scan_address: Address = super::SIG_MONO_64
            .scan_process_range(process, (root_domain_function_address, 0x100))?
            + 3;

        let assemblies = MonoPtr64(
            Address64::new(
                scan_address.value() + 0x4 + process.read::<i32>(scan_address).ok()? as u64,
            ),
            PhantomData::<MonoPtr64<GList>>,
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
    data: MonoPtr64<MonoAssembly>,
    next: MonoPtr64<GList>,
    prev: MonoPtr64<GList>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssembly {
    ref_count: i32,
    _padding: [u8; 4],
    basedir: MonoPtr64<CStr>,
    aname: MonoAssemblyName,
    image: MonoPtr64<MonoImage>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssemblyName {
    name: MonoPtr64<CStr>,
    culture: MonoPtr64<CStr>,
    hash_value: MonoPtr64<CStr>,
    public_key: MonoPtr64,
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
    without_version: u8,
    without_culture: u8,
    without_public_key_token: u8,
    _padding2: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoImage {
    ref_count: i32,
    _padding: [u8; 4],
    storage: MonoPtr64, // MonoImageStorage
    raw_data: MonoPtr64<u8>,
    raw_data_len: u32,
    various_flags: [u8; 2],
    _padding0: [u8; 2],
    name: MonoPtr64<CStr>,
    filename: MonoPtr64<CStr>,
    assembly_name: MonoPtr64<CStr>,
    module_name: MonoPtr64<CStr>,
    time_date_stamp: u32,
    _padding1: [u8; 4],
    version: MonoPtr64<CStr>,
    md_version_major: i16,
    md_version_minor: i16,
    _padding2: [u8; 4],
    guid: MonoPtr64<CStr>,
    image_info: MonoPtr64, // MonoCLIImageInfo
    mempool: MonoPtr64,    // MonoMemPool
    raw_metadata: MonoPtr64<u8>,
    heap_strings: MonoStreamHeader,
    heap_us: MonoStreamHeader,
    heap_blob: MonoStreamHeader,
    heap_guid: MonoStreamHeader,
    heap_tables: MonoStreamHeader,
    heap_pdb: MonoStreamHeader,
    tables_base: MonoPtr64<u8>,
    referenced_tables: u64,
    referenced_table_rows: MonoPtr64<i32>,
    tables: [MonoTableInfo; 56],
    references: MonoPtr64<MonoPtr64<MonoAssembly>>,
    nreferences: i32,
    _padding3: [u8; 4],
    modules: MonoPtr64<MonoPtr64<MonoImage>>,
    module_count: u32,
    _padding4: [u8; 4],
    modules_loaded: MonoPtr64<u8>,
    files: MonoPtr64<MonoPtr64<MonoImage>>,
    file_count: u32,
    _padding5: [u8; 4],
    aot_module: MonoPtr64, // MonoAotModule
    aotid: [u8; 16],
    assembly: MonoPtr64<MonoAssembly>,
    method_cache: MonoPtr64, // GHashTable
    class_cache: MonoInternalHashTable,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoStreamHeader {
    data: MonoPtr64<u8>,
    size: u32,
    _padding: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoTableInfo {
    base: MonoPtr64<u8>,
    rows_and_size: u32,
    size_bitfield: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoInternalHashTable {
    hash_func: MonoPtr64<u32>,
    key_extract: MonoPtr64,
    next_value: MonoPtr64,
    size: i32,
    num_entries: i32,
    table: MonoPtr64<MonoPtr64<MonoClassDef>>,
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
                .unwrap_or(MonoPtr64(Address64::NULL, PhantomData));
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
    _padding: [u8; 4],
    next_class_cache: MonoPtr64<MonoClassDef>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClass {
    element_class: MonoPtr64<MonoClass>,
    cast_class: MonoPtr64<MonoClass>,
    supertypes: MonoPtr64<MonoPtr64<MonoClass>>,
    idepth: u16,
    rank: u8,
    class_kind: u8,
    instance_size: i32,
    flags1: u32,
    min_align: u8,
    _padding2: [u8; 3],
    flags2: u32,
    _padding3: [u8; 4],
    parent: MonoPtr64<MonoClassDef>, // MonoClass
    nested_in: MonoPtr64<MonoClass>,
    image: MonoPtr64<MonoImage>,
    name: MonoPtr64<CStr>,
    name_space: MonoPtr64<CStr>,
    type_token: u32,
    vtable_size: i32,
    interface_count: u16,
    _padding4: [u8; 2],
    interface_id: u32,
    max_interface_id: u32,
    interface_offset_count: u16,
    _padding5: [u8; 2],
    interfaces_packed: MonoPtr64<MonoPtr64<MonoClass>>,
    interface_offsets_packed: MonoPtr64<u16>,
    interface_bitmap: MonoPtr64<u8>,
    interfaces: MonoPtr64<MonoPtr64<MonoClass>>,
    sizes: i32,
    _padding6: [u8; 4],
    fields: MonoPtr64<MonoClassField>,
    methods: MonoPtr64<MonoPtr64>, // MonoMethod
    this_arg: MonoType,
    byval_arg: MonoType,
    gc_descr: MonoPtr64,
    runtime_info: MonoPtr64<MonoClassRuntimeInfo>, // MonoClassRuntimeInfo
    vtable: MonoPtr64<MonoPtr64>,                  // MonoMethod
    infrequent_data: MonoPtr64,                    // MonoPropertyBag
    user_data: MonoPtr64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoClassRuntimeInfo {
    max_domain: u16,
    _padding: [u8; 6],
    domain_vtables: MonoPtr64<MonoVTable>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
struct MonoVTable {
    klass: MonoPtr64<MonoClass>,
    gc_descr: MonoPtr64, // MonoGCDescriptor = sizeof(Ptr)
    domain: MonoPtr64,   // MonoDomain
    r#type: MonoPtr64,
    interface_bitmap: MonoPtr64<u8>,
    max_interface_id: u16,
    rank: u8,
    initialized: u8,
    flags: u8,
    _padding: [u8; 3],
    more_flags: u32,
    imt_collisions_bitmap: u32,
    runtime_generic_context: MonoPtr64,
    interp_vtable: MonoPtr64,
    vtable: MonoPtr64,
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
            .byte_offset(mem::size_of::<MonoVTable>() as u64 - mem::size_of::<MonoPtr64>() as u64) // hack
            .cast::<MonoPtr64>()
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
    data: MonoPtr64,
    attrs: u16,
    r#type: u8,
    flags: u8,
    _padding: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClassField {
    r#type: MonoPtr64<MonoType>,
    name: MonoPtr64<CStr>,
    parent: MonoPtr64<MonoClass>,
    offset: i32,
    _padding: [u8; 4],
}
