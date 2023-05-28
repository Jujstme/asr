use bytemuck::{Zeroable, Pod};
use crate::{Process, Address, Error};
use super::{CStr, MonoPtr64};

pub struct MonoModule<'a> {
    process: &'a Process,
    assemblies: MonoPtr64<MonoPtr64<MonoAssembly>>,
    type_info_definition_table: MonoPtr64<MonoPtr64<MonoClass>>,
}

impl<'a> MonoModule<'a> {
    pub fn attach(process: &'a Process) -> Option<Self> {
        let mono_module = process.get_module_range("GameAssembly.dll").ok()?;

        let addr = super::SIG_64_ASSEMBLIES_TRG_IL2CPP.scan_process_range(process, mono_module)? + 12;
        let assemblies_trg_addr = addr + 0x4 + process.read::<i32>(addr).ok()?;
        let assemblies: MonoPtr64<MonoPtr64<MonoAssembly>> = process.read(assemblies_trg_addr).ok()?;

        let addr = super::SIG_64_TYPE_INFO_DEFINITION_TABLE_TRG
            .scan_process_range(process, mono_module)?
            .add_signed(-4);

        let type_info_definition_table_trg_addr = addr + 0x4 + process.read::<i32>(addr).ok()?;
        
        let type_info_definition_table: MonoPtr64<MonoPtr64<MonoClass>> =
            process.read(type_info_definition_table_trg_addr).ok()?;

        Some(Self {
            process,
            assemblies,
            type_info_definition_table,
        })
    }

    pub fn get_image(&self, assembly_name: &str) -> Option<MonoImageContainer<'_>> {
        let mut assemblies = self.assemblies;

        let image = loop {
            let ptr = assemblies.read(self.process).ok()?;
            if ptr.is_null() {
                return None;
            }

            let mono_assembly = ptr.read(self.process).ok()?;

            let this_name = mono_assembly.aname.name.read_str::<128>(self.process).ok()?;
            let this_name = &this_name[..this_name.iter().position(|&b| b == 0).unwrap_or(this_name.len())];
            
            if this_name == assembly_name.as_bytes()
            {
                break mono_assembly.image.read(self.process).ok()?;
            }
            assemblies = assemblies.offset(1);
        };
        Some(MonoImageContainer {
            mono_module: self,
            mono_image: image,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssembly {
    image: MonoPtr64<MonoImage>,
    token: u32,
    referenced_assembly_start: i32,
    referenced_assembly_count: i32,
    _padding: [u8; 4],
    aname: MonoAssemblyName,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoAssemblyName {
    name: MonoPtr64<CStr>,
    culture: MonoPtr64<CStr>,
    public_key: MonoPtr64<u8>,
    hash_alg: u32,
    hash_len: i32,
    flags: u32,
    major: i32,
    minor: i32,
    build: i32,
    revision: i32,
    public_key_token: [u8; 8],
    _padding: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoImage {
    name: MonoPtr64<CStr>,
    name_no_ext: MonoPtr64<CStr>,
    assembly: MonoPtr64<MonoAssembly>,
    type_start: i32,
    type_count: u32,
    exported_type_start: i32,
    exported_type_count: u32,
    custom_attribute_start: i32,
    custom_attribute_count: u32,
    entry_point_index: i32,
    _padding: [u8; 4],
    name_to_class_hash_table: MonoPtr64,
    token: u32,
    dynamic: u8,
    _padding2: [u8; 3],
}

pub struct MonoImageContainer<'a> {
    mono_module: &'a MonoModule<'a>,
    mono_image: MonoImage,
}

impl MonoImageContainer<'_> {
    fn classes(&self) -> Result<impl Iterator<Item = MonoClass> + '_, Error> {
        let ptr = self
            .mono_module
            .type_info_definition_table
            .offset(self.mono_image.type_start as _);
        Ok(
            (0..self.mono_image.type_count as usize).filter_map(move |i| {
                let class_ptr = ptr.index(self.mono_module.process, i).ok()?;
                if class_ptr.is_null() {
                    None
                } else {
                    class_ptr.read(self.mono_module.process).ok()
                }
            }),
        )
    }

    pub fn get_class(&self, class_name: &str) -> Option<MonoClassContainer<'_>> {
        let mut classes = self.classes().ok()?;
        classes
            .find(|c| {
                if let Ok(success) = c.name.read_str::<128>(self.mono_module.process) {
                    let success = &success[..success.iter().position(|&b| b == 0).unwrap_or(success.len())];
                    success == class_name.as_bytes() && !c.fields.is_null()
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
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClass {
    image: MonoPtr64<MonoImage>,
    gc_desc: MonoPtr64,
    name: MonoPtr64<CStr>,
    name_space: MonoPtr64<CStr>,
    byval_arg: MonoType,
    this_arg: MonoType,
    element_class: MonoPtr64<MonoClass>,
    cast_class: MonoPtr64<MonoClass>,
    declaring_type: MonoPtr64<MonoClass>,
    parent: MonoPtr64<MonoClass>,
    generic_class: MonoPtr64, // MonoGenericClass
    type_definition: MonoPtr64,
    interop_data: MonoPtr64,
    klass: MonoPtr64<MonoClass>,
    fields: MonoPtr64<MonoClassField>,
    events: MonoPtr64, // EventInfo
    properties: MonoPtr64, // PropertyInfo
    methods: MonoPtr64<MonoPtr64>, // MethodInfo
    nested_types: MonoPtr64<MonoPtr64<MonoClass>>,
    implemented_interfaces: MonoPtr64<MonoPtr64<MonoClass>>,
    interface_offsets: MonoPtr64,
    static_fields: MonoPtr64,
    rgctx_data: MonoPtr64,
    type_hierarchy: MonoPtr64<MonoPtr64<MonoClass>>,
    unity_user_data: MonoPtr64,
    initialization_exception_gc_handle: u32,
    cctor_started: u32,
    cctor_finished: u32,
    _padding: [u8; 4],
    cctor_thread: u64,
    generic_container_index: i32,
    instance_size: u32,
    actual_size: u32,
    element_size: u32,
    native_size: i32,
    static_fields_size: u32,
    thread_static_fields_size: u32,
    thread_static_fields_offset: i32,
    flags: u32,
    token: u32,
    method_count: u16,
    property_count: u16,
    field_count: u16,
    event_count: u16,
    nested_type_count: u16,
    vtable_count: u16,
    interfaces_count: u16,
    interface_offsets_count: u16,
    type_hierarchy_depth: u8,
    generic_recursion_depth: u8,
    rank: u8,
    minimum_alignment: u8,
    natural_alignment: u8,
    packing_size: u8,
    more_flags: [u8; 2],
}

pub struct MonoClassContainer<'a> {
    mono_module: &'a MonoModule<'a>,
    mono_class: MonoClass,
}

impl MonoClassContainer<'_> {
    fn fields(&self) -> impl Iterator<Item = MonoClassField> + '_ {
        (0..self.mono_class.field_count as usize)
            .flat_map(|i| self.mono_class.fields.index(self.mono_module.process, i))
    }

    pub fn get_field(&self, name: &str) -> Option<u64> {
        Some(
            self.fields()
                .find(|field| {
                    let Ok(field_name) = field
                        .name
                        .read_str::<128>(self.mono_module.process) else { return false };

                        let field_name = &field_name[..field_name.iter().position(|&b| b == 0).unwrap_or(field_name.len())];
                        field_name == name.as_bytes()
                })?
                .offset as _,
        )
    }

    pub fn get_static_table(&self) -> Option<Address> {
        let addr = self.mono_class.static_fields.get();

        if addr.is_null() {
            None
        } else {
            Some(addr)
        }
    }

    pub fn get_parent(&self) -> Option<MonoClassContainer<'_>> {
        let parent = self.mono_class.parent.read(self.mono_module.process).ok()?;
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
    attrs: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoClassField {
    name: MonoPtr64<CStr>,
    r#type: MonoPtr64<MonoType>,
    parent: MonoPtr64<MonoClass>,
    offset: i32,
    token: u32,
}