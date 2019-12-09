# Node application for browsing SMB shares through HTTP

This applications allows to browse SMB shares through HTTP (or HTTPS, 
using a reverse proxy).

## Configuration

This application is configured through a configuration file at ```config/config.json```
or at the location given as a (single) command line argument.

```javascript
{
	"shares": {
		"first-share": "\\\\my.first.server\\share",
		"second-share": "\\\\my.second.server\\share"
	}, 
	"domain": "my.logon.domain",
	"legalNoticeUrl": "https://my.company/legal/", 
	"privacyUrl": "https://my.company/privacy/", 
	"externalUrl": "http://smb-browser.my.company", 
	"allowSharing": true,
	"serverPort": 80
}
```

As a minimum configuration, an object ```shares``` has to be defined that 
configures the SMB shares to show. Additionally, ```domain``` should give 
the logon domain for the SMB server.

The properties ```legalNoticeUrl``` and ```privacyUrl``` can be set to 
show links to legal notice or privacy pages (if required by law).

If ```allowSharing``` is set to ```true```, smb-browser allows to create 
links for files that can be accessed without login (as long as the person 
who created the link is still logged in). The parameter ```externalUrl``` 
is used with share links and allows to ensure that the link addresses 
the right server (that knows the session) even when using it behind a load 
balancer.

## License

(The MIT License)

Copyright (c) 2019 Andreas Schierl &lt;github@schierla.de&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
