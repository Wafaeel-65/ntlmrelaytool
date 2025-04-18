/*==============================================================*/
/* Nom de SGBD :  MySQL 5.0                                     */
/* Date de cr�ation :  10/04/2025 16:04:05                      */
/*==============================================================*/

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS dsi;
USE dsi;

drop table if exists EXECUTE;

drop table if exists PLUGIN;

drop table if exists RESULTAT;

drop table if exists UTILISATEUR;

/*==============================================================*/
/* Table : EXECUTE                                              */
/*==============================================================*/
create table EXECUTE
(
   ID_UTILISATEUR       int not null,
   ID_PLUGIN            int not null,
   DATE_EXECUTION       datetime,
   primary key (ID_UTILISATEUR, ID_PLUGIN)
);

/*==============================================================*/
/* Table : PLUGIN                                               */
/*==============================================================*/
create table PLUGIN
(
   ID_PLUGIN            int not null,
   NOM_PLUGIN           varchar(100),
   DATE_CREATION        datetime,
   DESCRIPTION          text,
   VERSION              varchar(20),
   NTLM_KEY             varchar(255),
   primary key (ID_PLUGIN)
);

/*==============================================================*/
/* Table : RESULTAT                                             */
/*==============================================================*/
create table RESULTAT
(
   ID_RESULTAT          int not null,
   ID_PLUGIN            int not null,
   DATE_RESULTAT        datetime,
   STATUT               varchar(50),
   DETAILS              text,
   primary key (ID_RESULTAT)
);

/*==============================================================*/
/* Table : UTILISATEUR                                          */
/*==============================================================*/
create table UTILISATEUR
(
   ID_UTILISATEUR       int not null,
   PRENOM_UTILISATEUR   varchar(100),
   ROLE_UTILISATEUR     varchar(50),
   EMAIL_UTILISATEUR    varchar(100),
   DERNIERE_CONNEXION   datetime,
   primary key (ID_UTILISATEUR)
);

alter table EXECUTE add constraint FK_EXECUTE foreign key (ID_PLUGIN)
      references PLUGIN (ID_PLUGIN) on delete restrict on update restrict;

alter table EXECUTE add constraint FK_EXECUTE2 foreign key (ID_UTILISATEUR)
      references UTILISATEUR (ID_UTILISATEUR) on delete restrict on update restrict;

alter table RESULTAT add constraint FK_GENERE foreign key (ID_PLUGIN)
      references PLUGIN (ID_PLUGIN) on delete restrict on update restrict;

