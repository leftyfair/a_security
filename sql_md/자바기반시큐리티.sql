drop table member_auth2;
drop table member_sec02; 
drop sequence member_sec02_seq;

-- 회원 테이블
create sequence member_sec02_seq;
create table member_sec02(
    mno number(10) primary key, 
    memberId varchar2(50) unique not null,
    password varchar2(200)not null, 
    email varchar2(200), 
    enabled char(1) default(1)
);

-- 권한 테이블
create table member_auth2(
    memberId varchar2(50) not null, 
    memberType varchar2(50) not null, 
	ordinal number(10) not null,
    constraint fk_member_auth2 foreign key(memberId)
    references member_sec02(memberId)
);

select * from member_sec02;
select * from member_auth2;