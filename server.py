#!/usr/bin/python
# -*- coding: utf-8 -*-

# pip install flask

import flask

app = flask.Flask(__name__)

@app.route('/', methods = [ 'GET' ])
def index():
	return 'no keyword'

@app.route('/test', methods = [ 'GET' ])
def test():
	return 'page contains "fuck" keyword'

app.run(
	host = '0.0.0.0',
	port = 80,
	debug = True
)
