ALTER TABLE USERS_ROLES DROP CONSTRAINT FK_USERS_ROLES_USERNAME;
ALTER TABLE USERS_ROLES DROP CONSTRAINT FK_USERS_ROLES_ROLENAME;
DROP TABLE USERS CASCADE;
DROP TABLE ROLES CASCADE;
DROP TABLE MESSAGE CASCADE;
DROP TABLE USERS_ROLES CASCADE;
DELETE FROM SEQUENCE WHERE SEQ_NAME = 'SEQ_GEN';
