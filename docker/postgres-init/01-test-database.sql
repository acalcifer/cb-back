-- Creates the database the Go test suite uses.
--
-- Tests write real users and rooms, so pointing them at the development
-- database fills the room directory with fixtures. A separate database keeps
-- the two apart; TEST_DATABASE_URL in .env selects it.
--
-- This runs only when the postgres volume is first initialised. On an existing
-- volume, create it by hand:
--   docker compose exec postgres createdb -U cbback cbback_test
CREATE DATABASE cbback_test;
