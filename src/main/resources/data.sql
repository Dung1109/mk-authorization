insert into users(username, password, enabled)
values
    ('u', '{noop}1', true),
    ('a', '{noop}1', true);

insert into authorities(username, authority) values
                                                 ('a', 'ROLE_ADMIN'),
                                                 ('a', 'ROLE_USER'),
                                                 ('u', 'ROLE_USER');
