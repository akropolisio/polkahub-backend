table! {
    users (id) {
        id -> Int8,
        login -> Text,
        email -> Text,
        password -> Text,
        email_verified -> Bool,
        token -> Nullable<Text>,
        token_expired_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}
