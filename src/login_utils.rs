use names::{Generator, Name};

pub(crate) fn login() -> String {
    Generator::with_naming(Name::Numbered)
        .next()
        .expect("can not get random login")
}
