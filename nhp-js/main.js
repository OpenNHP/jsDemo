import {buildNHPPacket, parseNHPPacket} from "./dist/nhp-js-lib.js"

const privateKeyBase641 = "QL2U9Ag18Fqdc1Bpw4wx/sNJbFqq36rfhtkPm2WId1c=";
const publicKeyBase641 = "Z0QA6bPlRpq8xWsVFe8NGR43bjGHjK0mX7CT1daudAA=";
const privateKeyBase642 = "oLqkmcl6wVqUaOOrGo4xvpaUkuCThgM37DUZKGExFVE=";
const publicKeyBase642 = "E3o8gUUxI5dUAUiEOi6SvgV9bWKmjpWWQaOO6GChO2A=";
const packet = await buildNHPPacket(2, privateKeyBase641, publicKeyBase641, publicKeyBase642, "this is a test packet", true, "")
console.log("packet: ", packet)

const obj = await parseNHPPacket(packet, privateKeyBase642, publicKeyBase642, publicKeyBase641)
console.log("obj: ", obj)
