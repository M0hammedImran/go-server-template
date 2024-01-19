-- admin password is "q1w2e3r4"
-- mohammedimran86992@gmail.com password is "q1w2e3r4t5"
INSERT INTO public.users (
        created_at,
        updated_at,
        deleted_at,
        "name",
        email,
        "password",
        "uuid",
        "role",
        otp,
        first_name,
        last_name,
        otp_expiry
    )
VALUES (
        now(),
        now(),
        NULL,
        'Bywatt Admin',
        'admin@bywatt.com',
        '$2a$10$I56vTMR40YXNSoCItpWclONA/438YiAuBZWdv7PVplPPcSn4OgY.2',
        '4e7a79e7-ea39-403b-bf0c-f3211823037c',
        'admin',
        NULL,
        NULL,
        NULL,
        NULL
    );
INSERT INTO public.users (
        deleted_at,
        "name",
        email,
        "password",
        "uuid",
        "role",
        otp,
        first_name,
        last_name,
        otp_expiry
    )
VALUES (
        now(),
        now(),
        NULL,
        'Bywatt Admin',
        'mohammedimran86992@gmail.com',
        '$2a$10$xdK1Og5y9aC20qBdiJZBCeHVHL9yhNo..yb6y6N2hfrV0qybSyFF2',
        '76e3eda0-44b6-498f-aa0f-a63d2089840d',
        'admin',
        '',
        NULL,
        NULL,
        NULL
    )
