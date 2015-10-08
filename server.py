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

@app.route('/song', methods = [ 'GET' ])
def song():
	return 'First couple of years you had me fooled\nYour masquerade smile, and phony tears\n\nI really believed the games you played\nBut now you know I\'m no one\'s fool\n\nI am so strong\nI\'m feeling so strong\nI will never cry for you, boy\nNo tears\nNo damn tears\nThis won\'t bring me down\nI\'m gonna carry on now\nCoz I\'m so strong\nIt was make-believe it could not last\nI\'m learning that now as I erase the past\n\nYou made me stronger, you made me see\nThat I can live through anything\n\nI am so strong\nI\'m feeling so strong\nI will never cry for you, boy\nNo tears\nNo damn tears\nThis won\'t bring me down\nI\'m gonna carry on now\nCoz I\'m so strong\n\nI really believed you honestly cared\nIt seems I was wrong\nAnd now I\'m alone\nI can\'t say I mind\nI\'m better off without you\n\nI\'ve been so blind\nI could not see that you were faking everything\nSo cold, I\'ve felt so cold\nBut I won\'t let it bring me down\nNo tears, no damn tears\nI\'m gonna carry on now\nCoz I\'m so strong'

app.run(
	host = '0.0.0.0',
	port = 80,
	debug = True
)