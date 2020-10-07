--- insert roles
insert into roles select * from (
select 1, 'ROLE_USER' union
select 2, 'ROLE_ADMIN' union
select 3, 'ROLE_MODERATOR' union
select 4, 'ROLE_UNCONFIRMED'
) x where not exists(select * from roles);