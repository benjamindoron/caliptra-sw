// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with caliptra-rtl repo at 7d0fe340cbed88ea49d27a54fee52ac3c336276c
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
/// A zero-sized type that represents ownership of this
/// peripheral, used to get access to a Register lock. Most
/// programs create one of these in unsafe code near the top of
/// main(), and pass it to the driver responsible for managing
/// all access to the hardware.
pub struct PvReg {
    _priv: (),
}
impl PvReg {
    pub const PTR: *mut u32 = 0x1001a000 as *mut u32;
    /// # Safety
    ///
    /// Caller must ensure that all concurrent use of this
    /// peripheral in the firmware is done so in a compatible
    /// way. The simplest way to enforce this is to only call
    /// this function once.
    #[inline(always)]
    pub unsafe fn new() -> Self {
        Self { _priv: () }
    }
    /// Returns a register block that can be used to read
    /// registers from this peripheral, but cannot write.
    #[inline(always)]
    pub fn regs(&self) -> RegisterBlock<ureg::RealMmio> {
        RegisterBlock {
            ptr: Self::PTR,
            mmio: core::default::Default::default(),
        }
    }
    /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub fn regs_mut(&mut self) -> RegisterBlock<ureg::RealMmioMut> {
        RegisterBlock {
            ptr: Self::PTR,
            mmio: core::default::Default::default(),
        }
    }
}
#[derive(Clone, Copy)]
pub struct RegisterBlock<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio>> {
    ptr: *mut u32,
    mmio: TMmio,
}
impl<TMmio: ureg::Mmio + core::default::Default> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    #[inline(always)]
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self {
            ptr,
            mmio: core::default::Default::default(),
        }
    }
}
impl<TMmio: ureg::Mmio> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    #[inline(always)]
    pub unsafe fn new_with_mmio(ptr: *mut u32, mmio: TMmio) -> Self {
        Self { ptr, mmio }
    }
    /// Controls for each pcr entry
    ///
    /// Read value: [`pv::regs::PvctrlReadVal`]; Write value: [`pv::regs::PvctrlWriteVal`]
    #[inline(always)]
    pub fn pcr_ctrl(&self) -> ureg::Array<32, ureg::RegRef<crate::pv::meta::PcrCtrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Pcr Entries are read only
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    #[inline(always)]
    pub fn pcr_entry(
        &self,
    ) -> ureg::Array<32, ureg::Array<12, ureg::RegRef<crate::pv::meta::PcrEntry, &TMmio>>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x600 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct PvctrlReadVal(u32);
    impl PvctrlReadVal {
        /// Lock the PCR from being cleared
        #[inline(always)]
        pub fn lock(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Clear the data stored in this entry. Lock will prevent this clear.
        #[inline(always)]
        pub fn clear(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd0(&self) -> bool {
            ((self.0 >> 2) & 1) != 0
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd1(&self) -> u32 {
            (self.0 >> 3) & 0x1f
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> PvctrlWriteVal {
            PvctrlWriteVal(self.0)
        }
    }
    impl From<u32> for PvctrlReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<PvctrlReadVal> for u32 {
        #[inline(always)]
        fn from(val: PvctrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct PvctrlWriteVal(u32);
    impl PvctrlWriteVal {
        /// Lock the PCR from being cleared
        #[inline(always)]
        pub fn lock(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Clear the data stored in this entry. Lock will prevent this clear.
        #[inline(always)]
        pub fn clear(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd0(self, val: bool) -> Self {
            Self((self.0 & !(1 << 2)) | (u32::from(val) << 2))
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd1(self, val: u32) -> Self {
            Self((self.0 & !(0x1f << 3)) | ((val & 0x1f) << 3))
        }
    }
    impl From<u32> for PvctrlWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<PvctrlWriteVal> for u32 {
        #[inline(always)]
        fn from(val: PvctrlWriteVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    pub mod selector {}
}
pub mod meta {
    //! Additional metadata needed by ureg.
    pub type PcrCtrl =
        ureg::ReadWriteReg32<0, crate::pv::regs::PvctrlReadVal, crate::pv::regs::PvctrlWriteVal>;
    pub type PcrEntry = ureg::ReadOnlyReg32<u32>;
}
