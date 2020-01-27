table! {
    user_projects (id) {
        id -> Int8,
        user_id -> Int8,
        name -> Text,
        version -> Text,
        description -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

table! {
    users (id) {
        id -> Int8,
        login -> Text,
        email -> Text,
        password -> Text,
        email_verified -> Bool,
        email_verification_token -> Nullable<Text>,
        token -> Nullable<Text>,
        token_expired_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

joinable!(user_projects -> users (user_id));

allow_tables_to_appear_in_same_query!(user_projects, users,);
