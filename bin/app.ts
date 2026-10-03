#!/usr/bin/env node
import 'source-map-support/register';
import { App } from 'aws-cdk-lib/core';
import { buildApp } from '../lib/app';

buildApp(new App());
