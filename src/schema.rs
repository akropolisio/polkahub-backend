table! {
    users (id) {
        id -> Int8,
        email -> Text,
        password -> Text,
        email_verified -> Bool,
        token -> Nullable<Text>,
        token_expiried_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}
