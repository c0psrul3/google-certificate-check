#!/usr/local/bin/python

import xml.parsers.expat
import httplib
import tempfile
import subprocess

class XMLNode:
    def __init__(self, parent, name, attrs):
        self.parent = parent
        self.name = name
        self.attrs = attrs
        self.children = {}
        self.data = ''

    def addData(self, data):
        self.data += data

    def add(self, name, attrs):
        if name not in self.children:
            self.children[name] = []
        node = XMLNode(self, name, attrs)
        self.children[name].append(node)
        return node

    def __str__(self):
        s = ''
        for name in self.children:
            if s != '':
                s += ', '
            c = ''
            for child in self.children[name]:
                if c != '':
                    c += ', '
                c += str(child)
            s += name + '[' + c + ']'
        return "XMLNode(" + self.name + ", " + str(self.attrs) + ', "' \
               + self.data + '", ' + s + ')'

    def getChild(self, name):
        return self.children[name]

    def getOneChildData(self, name):
        children = self.getChild(name)
        assert len(children) == 1
        return children[0].data

class TrustAnchorParser:
    def __init__(self, anchors):
        parser = xml.parsers.expat.ParserCreate()
        parser.StartElementHandler = self.startElement;
        parser.EndElementHandler = self.endElement
        parser.CharacterDataHandler = self.charData
        self._current = None
        parser.Parse(anchors)

    def push(self, name, attrs):
        if self._current is None:
            self._parsed = self._current = XMLNode(None, name, attrs)
        else:
            self._current = self._current.add(name, attrs)

    def pop(self, name):
        assert self._current.name == name
        self._current = self._current.parent

    def dump(self):
        print self._parsed

    def startElement(self, name, attrs):
#        print "start", name, attrs
        self.push(name, attrs)
        
    def endElement(self, name):
#        print "end", name
        self.pop(name)
        
    def charData(self, data):
#        print "data", data
        if data != '\n':
            self._current.addData(data)

    def getOneChild(self, name):
        return self._parsed.getOneChildData(name)

    def keys(self):
        self.dump()
        assert self._parsed.name == 'TrustAnchor'
        zone = self.getOneChild('Zone')
        assert zone == '.'
        digests = self._parsed.getChild('KeyDigest')
        out = ''
        for digest in digests:
            keyTag = digest.getOneChildData('KeyTag')
            algorithm = digest.getOneChildData('Algorithm')
            digestType = digest.getOneChildData('DigestType')
            digest = digest.getOneChildData('Digest')
            out += zone + ' 300 IN DS ' + keyTag + ' ' +algorithm + ' ' \
                   + digestType + ' ' + digest + '\n'
        return out

iana = httplib.HTTPConnection('data.iana.org')
iana.request('GET', '/root-anchors/root-anchors.xml')
res = iana.getresponse()
assert res.status == 200
xml2 = res.read()
xmlfile = tempfile.NamedTemporaryFile()
print xmlfile.name
xmlfile.write(xml2)
xmlfile.flush()

iana.request('GET', '/root-anchors/root-anchors.asc')
res = iana.getresponse()
assert res.status == 200
sig = res.read()
sigfile = tempfile.NamedTemporaryFile()
print sigfile.name
sigfile.write(sig)
sigfile.flush()

subprocess.check_call([ 'gpg', '--no-default-keyring', '--keyring',
                        './icann.pgp', '--verify', sigfile.name, xmlfile.name ])

parser = TrustAnchorParser(xml2)
keys = parser.keys()
print keys,
keyfile = open('keys', 'w')
keyfile.write(keys)
print "Root keys retrieved and verified"

