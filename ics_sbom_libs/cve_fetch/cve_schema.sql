-- SPDX-License-Identifier: LGPL-2.0-or-later
-- SPDX-FileCopyrightText: 2024 Ics inc.
-- SPDX-FileContributor: Qin Zhang <qzhang@ics.com>
-- SPDX-FileContributor: Michael Dingwall <mdingwall@ics.com>
-- SPDX-FileContributor: Boris Ralchenko <bralchenko@ics.com>
-- v1.0  : Initial DB design
-- v1.1  : Added indexing to the "cve_range" to searching that table.
-- v1.2  : Added the "status" table to keep track of the last time the data was downloaded/updated.
-- v2.0  : Added "vulnerable" to the "cve_range" table.
-- v3.0  : Added the CPE dictionary table.
-- v4.0  : Added configurations field to the cve_severity table.
BEGIN TRANSACTION;
DROP TABLE IF EXISTS "cve_range";
CREATE TABLE IF NOT EXISTS "cve_range" (
	"id"	                integer NOT NULL,
	"cve_number"            text NOT NULL,
	"vendor"	            text,
	"product"	            text,
	"version"	            text,
	"part_type"	            text,
	"cpe"		            text,
	"vulnerable"            integer,
	"versionStartIncluding"	text,
	"versionStartExcluding"	text,
	"versionEndIncluding"	text,
	"versionEndExcluding"	text,
	"data_source"	        text,
	PRIMARY KEY("id" AUTOINCREMENT)
);
DROP TABLE IF EXISTS "cve_severity";
CREATE TABLE IF NOT EXISTS "cve_severity" (
	"cve_number"	text NOT NULL,
	"severity"	    text,
	"description"	text,
	"score"	        integer,
	"cvss_version"	real,
	"cvss_vector"	text,
	"data_source"	text,
	"last_modified"	datetime,
	"configurations" text,
	PRIMARY KEY("cve_number")
);
DROP TABLE IF EXISTS "cve_weakness";
CREATE TABLE IF NOT EXISTS "cve_weakness" (
	"id"	        integer NOT NULL,
	"cve_number"	text NOT NULL,
	"value"	        text NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT),
	UNIQUE(cve_number, value) ON CONFLICT REPLACE
);
DROP TABLE IF EXISTS "status";
CREATE TABLE IF NOT EXISTS "status" (
    "key"   text NOT NULL,
    "value" text NOT NULL,
	UNIQUE(key) ON CONFLICT REPLACE
);
INSERT INTO "status" ("key", "value") VALUES ("version", "3.0");
DROP TABLE IF EXISTS "cpe_dictionary";
CREATE TABLE IF NOT EXISTS "cpe_dictionary" (
    "cpe_id"        text NOT NULL,
    "cpe"           text,
    "vendor"	    text,
	"product"	    text,
    "deprecated"    integer,
    "created"       datetime,
    "last_modified" datetime,
    PRIMARY KEY("cpe_id")
);
CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product);
COMMIT;
