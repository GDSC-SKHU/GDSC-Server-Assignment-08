-- create schema jwt
use jwt;

insert into member(member_id, password) values ('admin', '1234');
insert into member_roles(member_member_id, roles) values ('admin', 'ADMIN');


insert into member(member_id, password) values ('user', '3333');
insert into member_roles(member_member_id, roles) values ('user', 'USER');

