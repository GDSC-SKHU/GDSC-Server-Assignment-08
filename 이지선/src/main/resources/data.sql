use jwtexample;

insert into member(member_id, password) values ('admin', '1234');
insert into member_roles(member_member_id, roles) values ('admin', 'ADMIN');

insert into member(member_id, password) values ('user', '0000');
insert into member_roles(member_member_id, roles) values ('user', 'USER');