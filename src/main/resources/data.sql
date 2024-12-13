INSERT INTO users(username, password, enabled)
VALUES ('u', '{noop}1', TRUE),
       ('a', '{noop}1', TRUE);

INSERT INTO authorities(username, authority)
VALUES ('a', 'ROLE_ADMIN'),
       ('u', 'ROLE_MANAGER');

-- Insert data for username 'u'
INSERT INTO userinfo (
    username,
    full_name,
    picture,
    email,
    email_verified,
    gender,
    birthdate,
    phone_number,
    phone_number_verified,
    address,
    position,
    department,
    note,
    updated_at,
    created_at
) VALUES (
             'u',
             'User U',
             'https://example.com/images/u.jpg',
             'useru@example.com',
             TRUE,
             'male',
             '1995-03-25',
             '+1234567890',
             TRUE,
             '123 Rainbow St, Anytown, Wonderland',
             'Developer',
             'hr',
             'Key contributor to multiple projects.',
             NOW(),
             NOW()
         );

-- Insert data for username 'a'
INSERT INTO userinfo (
    username,
    full_name,
    picture,
    email,
    email_verified,
    gender,
    birthdate,
    phone_number,
    phone_number_verified,
    address,
    position,
    department,
    note,
    updated_at,
    created_at
) VALUES (
             'a',
             'Alice Anderson',
             'https://example.com/images/a.jpg',
             'alice@example.com',
             FALSE,
             'female',
             '1990-07-14',
             '+9876543210',
             FALSE,
             '456 Elm St, Othertown, Wonderland',
             'Manager',
             'it',
             'Oversees daily operations and team management.',
             NOW(),
             NOW()
         );
