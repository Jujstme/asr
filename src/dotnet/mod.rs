//! Support for games using the Unity engine.

use crate::{Process, Address64, Address, Error, Address32, future::retry, signature::Signature, file_format::pe};
use core::{mem, marker::PhantomData, cmp::Ordering};
use bytemuck::{Pod, Zeroable};

mod mono_v1_x86;
mod mono_v1_x64;
mod mono_v2_x86;
mod mono_v2_x64;
mod mono_v3_x64;
mod il2cpp_base;
mod il2cpp_2019;
mod il2cpp_2020;

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(missing_docs)]
pub enum MonoVersion {
    MonoV1_x86,
    MonoV1_x64,
    MonoV2_x86,
    MonoV2_x64,
    MonoV3_x64,
    Il2Cpp_base_x64,
    Il2Cpp_2019_x64,
    Il2Cpp_2020_x64,
}

#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum UnityManager<'a> {
    MonoV1_x86(mono_v1_x86::MonoModule<'a>),
    MonoV1_x64(mono_v1_x64::MonoModule<'a>),
    MonoV2_x86(mono_v2_x86::MonoModule<'a>),
    MonoV2_x64(mono_v2_x64::MonoModule<'a>),
    MonoV3_x64(mono_v3_x64::MonoModule<'a>),
    Il2Cpp_base(il2cpp_base::MonoModule<'a>),
    Il2Cpp_2019(il2cpp_2019::MonoModule<'a>),
    Il2Cpp_2020(il2cpp_2020::MonoModule<'a>),
}

impl<'a> UnityManager<'a> {
    /// Attaches to the target Mono process
    pub fn try_attach(process: &'a Process) -> Option<Self> {
        let version = detect_version(process)?;
        Self::attach(process, version)
    }

    /// Attaches to the target Mono process
    pub fn attach(process: &'a Process, version: MonoVersion) -> Option<Self> {
        match version {
            MonoVersion::MonoV1_x86 => Some(UnityManager::MonoV1_x86(mono_v1_x86::MonoModule::attach(process)?)),
            MonoVersion::MonoV1_x64 => Some(UnityManager::MonoV1_x64(mono_v1_x64::MonoModule::attach(process)?)),
            MonoVersion::MonoV2_x86 => Some(UnityManager::MonoV2_x86(mono_v2_x86::MonoModule::attach(process)?)),
            MonoVersion::MonoV2_x64 => Some(UnityManager::MonoV2_x64(mono_v2_x64::MonoModule::attach(process)?)),
            MonoVersion::MonoV3_x64 => Some(UnityManager::MonoV3_x64(mono_v3_x64::MonoModule::attach(process)?)),
            MonoVersion::Il2Cpp_base_x64 => Some(UnityManager::Il2Cpp_base(il2cpp_base::MonoModule::attach(process)?)),
            MonoVersion::Il2Cpp_2019_x64 => Some(UnityManager::Il2Cpp_2019(il2cpp_2019::MonoModule::attach(process)?)),
            MonoVersion::Il2Cpp_2020_x64 => Some(UnityManager::Il2Cpp_2020(il2cpp_2020::MonoModule::attach(process)?)),
        }
    }

    /// Looks for the specified binary image inside the target process.
    pub fn get_image(&'a self, assembly_name: &str) -> Option<MonoImage<'a>> {
        match self {
            Self::MonoV1_x86(x) => Some(MonoImage::MonoV1_x86(x.get_image(assembly_name)?)),
            Self::MonoV1_x64(x) => Some(MonoImage::MonoV1_x64(x.get_image(assembly_name)?)),
            Self::MonoV2_x86(x) => Some(MonoImage::MonoV2_x86(x.get_image(assembly_name)?)),
            Self::MonoV2_x64(x) => Some(MonoImage::MonoV2_x64(x.get_image(assembly_name)?)),
            Self::MonoV3_x64(x) => Some(MonoImage::MonoV3_x64(x.get_image(assembly_name)?)),
            Self::Il2Cpp_base(x) => Some(MonoImage::Il2Cpp_base(x.get_image(assembly_name)?)),
            Self::Il2Cpp_2019(x) => Some(MonoImage::Il2Cpp_2019(x.get_image(assembly_name)?)),
            Self::Il2Cpp_2020(x) => Some(MonoImage::Il2Cpp_2020(x.get_image(assembly_name)?)),
        }
    }

    /// Looks for the `Assembly-CSharp` binary image inside the target process
    pub fn get_default_image(&self) -> Option<MonoImage<'_>> {
        self.get_image("Assembly-CSharp")
    }

    /// Attaches to the target Mono process and internally gets the associated Mono assembly images.
    ///
    /// This function will return `None` is either:
    /// - The process is not identified as a valid IL2CPP game
    /// - The process is 32bit (64bit IL2CPP is not supported by this class)
    /// - The mono assemblies are not found
    ///
    /// This is the `await`able version of the `attach()` function,
    /// yielding back to the runtime between each try.
    pub async fn wait_attach(process: &'a Process, version: MonoVersion) -> UnityManager<'_> {
        retry(|| Self::attach(process, version)).await
    }

    /// Looks for the specified binary image inside the target process.
    ///
    /// This is the `await`able version of the `find_image()` function,
    /// yielding back to the runtime between each try.
    pub async fn wait_get_image(&self, assembly_name: &str) -> MonoImage<'_> {
        retry(|| self.get_image(assembly_name)).await
    }

    /// Looks for the `Assembly-CSharp` binary image inside the target process
    ///
    /// This is the `await`able version of the `find_default_image()` function,
    /// yielding back to the runtime between each try.
    pub async fn wait_get_default_image(&self) -> MonoImage<'_> {
        retry(|| self.get_default_image()).await
    }
}

#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum MonoImage<'a> {
    MonoV1_x86(mono_v1_x86::MonoImageContainer<'a>),
    MonoV1_x64(mono_v1_x64::MonoImageContainer<'a>),
    MonoV2_x86(mono_v2_x86::MonoImageContainer<'a>),
    MonoV2_x64(mono_v2_x64::MonoImageContainer<'a>),
    MonoV3_x64(mono_v3_x64::MonoImageContainer<'a>),
    Il2Cpp_base(il2cpp_base::MonoImageContainer<'a>),
    Il2Cpp_2019(il2cpp_2019::MonoImageContainer<'a>),
    Il2Cpp_2020(il2cpp_2020::MonoImageContainer<'a>),
}

impl MonoImage<'_> {
    /// Searches in memory for the specified `MonoClass`.
    ///
    /// Returns `Option<T>` if successful, `None` otherwise.
    pub fn get_class(&self, class_name: &str) -> Option<MonoClass<'_>> {
        match self {
            Self::MonoV1_x86(x) => Some(MonoClass::MonoV1_x86(x.get_class(class_name)?)),
            Self::MonoV1_x64(x) => Some(MonoClass::MonoV1_x64(x.get_class(class_name)?)),
            Self::MonoV2_x86(x) => Some(MonoClass::MonoV2_x86(x.get_class(class_name)?)),
            Self::MonoV2_x64(x) => Some(MonoClass::MonoV2_x64(x.get_class(class_name)?)),
            Self::MonoV3_x64(x) => Some(MonoClass::MonoV3_x64(x.get_class(class_name)?)),
            Self::Il2Cpp_base(x) => Some(MonoClass::Il2Cpp_base(x.get_class(class_name)?)),
            Self::Il2Cpp_2019(x) => Some(MonoClass::Il2Cpp_2019(x.get_class(class_name)?)),
            Self::Il2Cpp_2020(x) => Some(MonoClass::Il2Cpp_2020(x.get_class(class_name)?)),
        }
    }

    /// Search in memory for the specified `MonoClass`.
    pub async fn wait_get_class(&self, class_name: &str) -> MonoClass<'_> {
        retry(|| self.get_class(class_name)).await
    }
}

#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum MonoClass<'a> {
    MonoV1_x86(mono_v1_x86::MonoClassContainer<'a>),
    MonoV1_x64(mono_v1_x64::MonoClassContainer<'a>),
    MonoV2_x86(mono_v2_x86::MonoClassContainer<'a>),
    MonoV2_x64(mono_v2_x64::MonoClassContainer<'a>),
    MonoV3_x64(mono_v3_x64::MonoClassContainer<'a>),
    Il2Cpp_base(il2cpp_base::MonoClassContainer<'a>),
    Il2Cpp_2019(il2cpp_2019::MonoClassContainer<'a>),
    Il2Cpp_2020(il2cpp_2020::MonoClassContainer<'a>),
}

impl MonoClass<'_> {
    /// Finds the offset of a given field by its name
    pub fn get_field(&self, field_name: &str) -> Option<u64> {
        match self {
            Self::MonoV1_x86(x) => x.get_field(field_name),
            Self::MonoV1_x64(x) => x.get_field(field_name),
            Self::MonoV2_x86(x) => x.get_field(field_name),
            Self::MonoV2_x64(x) => x.get_field(field_name),
            Self::MonoV3_x64(x) => x.get_field(field_name),
            Self::Il2Cpp_base(x) => x.get_field(field_name),
            Self::Il2Cpp_2019(x) => x.get_field(field_name),
            Self::Il2Cpp_2020(x) => x.get_field(field_name),
        }
    }

    /// Returns the address of the static table for the current `MonoClass`
    pub fn get_static_table(&self) -> Option<Address> {
        match self {
            Self::MonoV1_x86(x) => x.get_static_table(),
            Self::MonoV1_x64(x) => x.get_static_table(),
            Self::MonoV2_x86(x) => x.get_static_table(),
            Self::MonoV2_x64(x) => x.get_static_table(),
            Self::MonoV3_x64(x) => x.get_static_table(),
            Self::Il2Cpp_base(x) => x.get_static_table(),
            Self::Il2Cpp_2019(x) => x.get_static_table(),
            Self::Il2Cpp_2020(x) => x.get_static_table(),
        }
    }

    /// Finds the parent `MonoClass` of the current class
    pub fn get_parent(&self) -> Option<MonoClass<'_>> {
        match self {
            Self::MonoV1_x86(x) => Some(MonoClass::MonoV1_x86(x.get_parent()?)),
            Self::MonoV1_x64(x) => Some(MonoClass::MonoV1_x64(x.get_parent()?)),
            Self::MonoV2_x86(x) => Some(MonoClass::MonoV2_x86(x.get_parent()?)),
            Self::MonoV2_x64(x) => Some(MonoClass::MonoV2_x64(x.get_parent()?)),
            Self::MonoV3_x64(x) => Some(MonoClass::MonoV3_x64(x.get_parent()?)),
            Self::Il2Cpp_base(x) => Some(MonoClass::Il2Cpp_base(x.get_parent()?)),
            Self::Il2Cpp_2019(x) => Some(MonoClass::Il2Cpp_2019(x.get_parent()?)),
            Self::Il2Cpp_2020(x) => Some(MonoClass::Il2Cpp_2020(x.get_parent()?)),
        }
    }

    /// Finds the offset of a given field by its name
    pub async fn wait_get_field(&self, name: &str) -> u64 {
        retry(|| self.get_field(name)).await
    }

    /// Returns the address of the static table for the current `MonoClass`
    pub async fn wait_get_static_table(&self) -> Address {
        retry(|| self.get_static_table()).await
    }

    /// Finds the parent `MonoClass` of the current class
    pub async fn wait_get_parent(&self) -> MonoClass<'_> {
        retry(|| self.get_parent()).await
    }
}


const SIG_64_ASSEMBLIES_TRG_IL2CPP: Signature<12> = Signature::new("48 FF C5 80 3C ?? 00 75 ?? 48 8B 1D");            
//const SIG_32_ASSEMBLIES_TRG_IL2CPP: Signature<9> = Signature::new("8A 07 47 84 C0 75 ?? 8B 35");
const SIG_64_TYPE_INFO_DEFINITION_TABLE_TRG: Signature<10> = Signature::new("48 83 3C ?? 00 75 ?? 8B C? E8");
//const SIG_32_TYPE_INFO_DEFINITION_TABLE_TRG: Signature<10> = Signature::new("C3 A1 ?? ?? ?? ?? 83 3C ?? 00");

const SIG_MONO_64: Signature<3> = Signature::new("48 8B 0D");
const SIG_MONO_32_1: Signature<2> = Signature::new("FF 35");
const SIG_MONO_32_2: Signature<2> = Signature::new("8B 0D");

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct CStr;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoPtr64<T = ()>(Address64, PhantomData<T>);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
struct MonoPtr32<T = ()>(Address32, PhantomData<T>);

impl<T: Pod> MonoPtr64<T> {
    fn get(&self) -> Address {
        self.0.into()
    }

    fn is_null(&self) -> bool {
        self.get().is_null()
    }

    fn offset(&self, count: u64) -> Self {
        Self(self.0 + count * mem::size_of::<T>() as u64, PhantomData)
    }

    fn read(&self, process: &Process) -> Result<T, Error> {
        process.read(self.get())
    }

    fn index(&self, process: &Process, idx: usize) -> Result<T, Error> {
        process.read(self.get() + (idx * mem::size_of::<T>()) as u64)
    }

    fn byte_offset(&self, bytes: u64) -> Self {
        Self(self.0 + bytes, PhantomData)
    }

    const fn cast<U>(&self) -> MonoPtr64<U> {
        MonoPtr64(self.0, PhantomData)
    }
}

impl MonoPtr64<CStr> {
    fn read_str<const N: usize>(&self, process: &Process) -> Result<[u8; N], Error> {
        process.read::<[u8; N]>(self.get())
    }
}

impl<T: Pod> MonoPtr32<T> {
    fn get(&self) -> Address {
        self.0.into()
    }

    fn is_null(&self) -> bool {
        self.get().is_null()
    }
/*
    fn offset(&self, count: u32) -> Self {
        Self(self.0 + count * mem::size_of::<T>() as u32, PhantomData)
    }
*/
    fn read(&self, process: &Process) -> Result<T, Error> {
        process.read(self.get())
    }

    fn index(&self, process: &Process, idx: usize) -> Result<T, Error> {
        process.read(self.get() + (idx * mem::size_of::<T>()) as u64)
    }

    fn byte_offset(&self, bytes: u32) -> Self {
        Self(self.0 + bytes, PhantomData)
    }

    const fn cast<U>(&self) -> MonoPtr32<U> {
        MonoPtr32(self.0, PhantomData)
    }
}

impl MonoPtr32<CStr> {
    fn read_str<const N: usize>(&self, process: &Process) -> Result<[u8; N], Error> {
        process.read::<[u8; N]>(self.get())
    }
}

struct MonoPEOffsets {
    signature: u32,
    export_directory_index_pe: u32,
    number_of_functions: u32,
    function_address_array_index: u32,
    function_name_array_index: u32,
    //function_entry_size: u32,
}

impl MonoPEOffsets {
    const fn new(is_64_bit: bool) -> Self {
        MonoPEOffsets {
            signature: 0x3C,
            export_directory_index_pe: if is_64_bit { 0x88 } else { 0x78 },
            number_of_functions: 0x14,
            function_address_array_index: 0x1C,
            function_name_array_index: 0x20,
            //function_entry_size: 0x4,
        }
    }
}

fn detect_version(process: &Process) -> Option<MonoVersion> {
    const SIG: Signature<25> = Signature::new("55 00 6E 00 69 00 74 00 79 00 20 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E");

    fn get_version_no(input: &[u8]) -> u32 {
        const ZERO: u8 = b'0';
        const ONE: u8 = b'1';
        const TWO: u8 = b'2';
        const THREE: u8 = b'3';
        const FOUR: u8 = b'4';
        const FIVE: u8 = b'5';
        const SIX: u8 = b'6';
        const SEVEN: u8 = b'7';
        const EIGHT: u8 = b'8';
        const NINE: u8 = b'9';
        let mut version: u32 = 0;
        for &val in input {
            match val {
                ZERO => version *= 10,
                ONE => version = version * 10 + 1,
                TWO => version = version * 10 + 2,
                THREE => version = version * 10 + 3,
                FOUR => version = version * 10 + 4,
                FIVE => version = version * 10 + 5,
                SIX => version = version * 10 + 6,
                SEVEN => version = version * 10 + 7,
                EIGHT => version = version * 10 + 8,
                NINE => version = version * 10 + 9,
                _ => break,
            }
        }
        version
    }

    if let Ok(gameassembly) = process.get_module_range("GameAssembly.dll") {
        let unity_module = process.get_module_range("UnityPlayer.dll").ok()?;

        if pe::MachineType::read(process, unity_module.0)? == pe::MachineType::X86 {
            return None;
        }

        let addr = SIG.scan_process_range(process, unity_module)? + 0x1E;
        let version_string = process.read::<[u16; 6]>(addr).ok()?;
        let version_string = version_string.map(|m| m as u8);
        let mut ver = version_string.split(|&b| b == b'.');

        let version = ver.next()?;
        let il2cpp = get_version_no(version);

        match il2cpp.cmp(&2019) {
            Ordering::Less => Some(MonoVersion::Il2Cpp_base_x64),
            Ordering::Equal => Some(MonoVersion::Il2Cpp_2019_x64),
            _ => {
                const SIG_METADATA: Signature<9> = Signature::new("4C 8B 05 ?? ?? ?? ?? 49 63");
                let Some(addr) = SIG_METADATA.scan_process_range(process, gameassembly) else { return Some(MonoVersion::Il2Cpp_2019_x64) };
                let addr: Address = addr + 3;
                let addr: Address = addr + 0x4 + process.read::<i32>(addr).ok()?;
                let version = process.read::<i32>(addr + 4).ok()?;

                match version.cmp(&27) {
                    Ordering::Less => Some(MonoVersion::Il2Cpp_2019_x64),
                    _ => Some(MonoVersion::Il2Cpp_2020_x64),
                }
            },
        }
    } else if let Ok(x) = process.get_module_address("mono.dll") {
        let is_64_bit = pe::MachineType::read(process, x)?;
        match is_64_bit {
            pe::MachineType::X86 => Some(MonoVersion::MonoV1_x86),
            _ => Some(MonoVersion::MonoV1_x64),
        }
    } else if process.get_module_address("mono-2.0-bdwgc.dll").is_ok() {
        let unity_module = process.get_module_range("UnityPlayer.dll").ok()?;

        let addr = SIG.scan_process_range(process, unity_module)? + 0x1E;
        let version_string = process.read::<[u16; 6]>(addr).ok()?;
        let version_string = version_string.map(|m| m as u8);
        let mut ver = version_string.split(|&b| b == b'.');
    
        let version = ver.next()?;
        let unity_version = get_version_no(version);
        
        let version = ver.next()?;
        let minor_version = get_version_no(version);

        let is_64_bit = pe::MachineType::read(process, unity_module.0)? == pe::MachineType::X86_64;

        if (unity_version == 2021 && minor_version >= 2) || (unity_version > 2021) {
            Some(MonoVersion::MonoV3_x64)
        } else {
            match is_64_bit {
                false => Some(MonoVersion::MonoV2_x86),
                true => Some(MonoVersion::MonoV2_x64),
            }
        }
    } else {
        None
    }
}
