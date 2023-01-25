/*global describe, it */

'use strict';

var assert = require('assert'),
    repeater = require('./');

describe('Repeater', function() {
    it('should repeat a pattern a certain number of times', function() {
        assert.equal( '.', repeater( '.', 1 ) );
        assert.equal( '...', repeater( '.', 3 ) );
        assert.equal( '...', repeater( '.', '3a' ) );
        assert.equal( '..........', repeater( '.', 10 ) );
    });

    it('should require a pattern and count', function() {
        assert.throws(function() {
            repeater();
        });
        assert.throws(function() {
            repeater( null, null );
        });
        assert.throws(function() {
            repeater('.');
        });
        assert.throws(function() {
            repeater( null, 3 );
        });
    });

    it('should require that pattern be a string', function() {
        assert.throws(function() {
            repeater( [ { pattern: '|' } ], 10 );
        });
    });
});
