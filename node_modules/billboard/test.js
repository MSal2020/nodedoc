/*global describe, it */

'use strict';

var assert = require('assert'),
    billboard = require('./');

describe('Billboard', function() {
    it('should display your message', function() {
        var expected = '\n.----------.\n| Welcome! |\n\'----------\'\n\n';

        assert.equal( expected, billboard('Welcome!') );
    });

    it('should allow custom prompt widths', function() {
        var expected = '\n.------------------.\n|     Welcome!     |\n\'------------------\'\n\n';

        assert.equal( expected, billboard('Welcome!', 20 ) );
    });

    it('should display at least as long as your message', function() {
        var expected = '\n.----------.\n| Welcome! |\n\'----------\'\n\n';

        assert.equal( expected, billboard('Welcome!', 3 ) );
    });

    it('should require a message', function() {
        assert.throws(function() {
            billboard();
        });
        assert.throws(function() {
            billboard( null, null );
        });
        assert.throws(function() {
            billboard( null, 20 );
        });
    });

    it('should require that message be a string', function() {
        assert.throws(function() {
            billboard( [ { pattern: '|' } ], 10 );
        });
    });
});
