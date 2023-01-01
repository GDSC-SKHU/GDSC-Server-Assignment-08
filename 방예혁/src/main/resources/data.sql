use gdscjwt;

insert into member(member_id, password)
values ('admin', '1234'),
       ('user', '5678');

insert into member_roles(member_member_id, roles)
values ('admin', 'ADMIN'),
       ('user', 'USER');