use std::borrow::Cow;

#[derive(Debug)]
pub struct Pdb<'a> {
    // NOTE I should probably always use `let data = &self.data as &[u8];` before using this
    //      to minimize the cost of the deref calls.
    data: Cow<'a, [u8]>,
}

impl<'a> Pdb<'a> {
    pub fn parse<C: Into<Cow<'a, [u8]>>>(data: C) -> Pdb<'a> {
        Pdb { data: data.into() }
    }
}
