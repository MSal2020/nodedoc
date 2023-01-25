# billboard [![Build Status](https://travis-ci.org/AutoConX/billboard.svg?branch=master)](https://travis-ci.org/AutoConX/billboard)

> Put a little signage around your message.


## API

```sh
$ npm install --save billboard
```

```js
var billboard = require('billboard');

console.log( billboard('Welcome!') );
//=>
//=> .----------.
//=> | Welcome! |
//=> '----------'
//=>

console.log( billboard('Welcome!', 20 ) );
//=>
//=> .------------------.
//=> |     Welcome!     |
//=> '------------------'
//=>
```


## Yeoman Support

You can use billboard with Yeoman generators. Just use the Yeoman generator log around your billboard.

```js
var yeoman = require('yeoman-generator'),
    billboard = require('billboard');

var SampleGenerator = yeoman.generators.Base.extend({
    initializing: function() {
        this.log( billboard('Welcome!', 20 ) );
    }
});

module.exports = SampleGenerator;
```


## License

MIT © [AutoConX](http://www.autoconx.com)
