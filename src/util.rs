use digest::Update;

/// Adapter to use [`digest::Update`] with [`std::io::Write`]
#[repr(transparent)]
pub struct WriteUpdate<D>(pub D);

impl<U> std::io::Write for WriteUpdate<U>
where
    U: Update,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
