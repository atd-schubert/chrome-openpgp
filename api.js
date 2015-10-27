/*jslint browser: true*/

/*globals chrome, openpgp*/

(function (exports) {
    'use strict';

    var secretKey,
        transmissionSecretKey = {},

        getProtoDomain = function (url) {
            var splitedUrl = url.split('/');
            return splitedUrl[0] + splitedUrl[2];
        },
        getCurrentTab = function (cb) {
            chrome.tabs.query({
                active: true,
                currentWindow: true
            }, function (tabs) {
                return cb(null, tabs[0]);
            });
        },
        readPublicKey = function (key) {
            if (typeof key === 'string') {
                key = openpgp.key.readArmored(key).keys;
            } else if (!key) {
                return [];
            }
            return key;
        },
        readSecretKey = function (key) {
            if (typeof key === 'string') {
                return openpgp.key.readArmored(key).keys[0];
            }
            return key;
        },
        isSecretKeyDecrypted = function (key) {
            return key.primaryKey.isDecrypted;
        },
        decryptSecretKey = function (key, passphrase) {
            if (typeof key === 'string') {
                key = readSecretKey(key);
            }
            if (!isSecretKeyDecrypted(key)) {
                key.decrypt(passphrase || window.prompt("Please enter password for your secret key"));
            }
            return key;
        },
        readMessage = function (message) {
            if (!message) {
                throw new Error('There is no message to read');
            }
            if (typeof message === 'string') {
                message = openpgp.message.readArmored(message);
            }
            return message;
        },
        getSecurePublicKey = function () {
            return readPublicKey(localStorage.getItem('pub'));
        },
        getTransmissionSecretKey = function (url) {
            var protoDomain = getProtoDomain(url);
            if (!transmissionSecretKey[protoDomain]) {
                transmissionSecretKey[protoDomain] = readSecretKey(localStorage.getItem('transmission-sec:' + protoDomain));
            }
            return transmissionSecretKey[protoDomain];
        },
        getTransmissionPublicKey = function (url) {
            return readPublicKey(localStorage.getItem('transmission-pub:' + getProtoDomain(url)));
        },
        getTransmissionServerKey = function (url) {
            return readPublicKey(localStorage.getItem('transmission-server:' + getProtoDomain(url)));
        },
        getTransmissionSignedPublicKey = function (url) {
            return localStorage.getItem('transmission-sign:' + getProtoDomain(url));
        },
        getSecureSecretKey = function () {
            if (!secretKey) {
                secretKey = readSecretKey(localStorage.getItem('sec'));
            }
            return secretKey;
        },
        decryptSecureSecretKey = function (passphrase) {
            return decryptSecretKey(getSecureSecretKey(), passphrase);
        },
        decryptTransmissionSecretKey = function (url, passphrase) {
            return decryptSecretKey(getTransmissionSecretKey(url), passphrase);
        },
        addMessage = function (message) {
            var messages = JSON.parse(localStorage.getItem('messages') || '[]');
            message.type = message.type || 'info';
            message.origin = message.origin || 'system';
            // message.encypted
            // message.verify
            message.id = Date.now().toString();

            chrome.browserAction.setBadgeText({
                text: messages.push(message).toString()
            });
            localStorage.setItem('messages', JSON.stringify(messages));
        },
        removeMessage = function (id) {
            var messages = JSON.parse(localStorage.getItem('messages') || '[]'), i;
            for (i = 0; i < messages.length; i += 1) {
                if (messages[i].id.toString() === id.toString()) {
                    messages.splice(i, 1);
                    if (messages.length) {
                        chrome.browserAction.setBadgeText({text: messages.length.toString()});
                    } else {
                        chrome.browserAction.setBadgeText({text: ''});
                    }
                    localStorage.setItem('messages', JSON.stringify(messages));
                    return;
                }
            }
        },
        getMessage = function (id) {
            var messages = JSON.parse(localStorage.getItem('messages') || '[]'), i;
            for (i = 0; i < messages.length; i += 1) {
                if (messages[i].id.toString() === id.toString()) {
                    return messages[i];
                }
            }
            return null;
        },

        encrypt = function (publicKey, message, cb) {
            try {
                publicKey = readPublicKey(publicKey);
                openpgp.encryptMessage(publicKey, message).then(function (pgpMessage) {
                    cb(null, pgpMessage);
                }).catch(function (error) {
                    cb(error);
                });
            } catch (err) {
                cb(err);
            }
        },
        encryptTransmission = function (message, cb, url) { // TODO: add additional publicKeys
            var goOn = function (err, tab) {
                if (err) {
                    return cb(err);
                }
                encrypt(getTransmissionServerKey(tab.url), message, cb);
            };
            if (!url) {
                getCurrentTab(goOn);
            }
            goOn(null, {url: url});
        },
        encryptSecure = function (message, cb) { // TODO: add additional publicKeys
            encrypt(getSecurePublicKey(), message, cb);
        },
        encryptSecureTransmission = function () {},// TODO....

        decrypt = function (secretKey, message, cb) {
            try {
                decryptSecretKey(secretKey);

                if (!isSecretKeyDecrypted(secretKey)) {
                    return cb(new Error('Secret-key is not decrypted'));
                }
                openpgp.decryptMessage(secretKey, readMessage(message)).then(function (plaintext) {
                    cb(null, plaintext);
                }).catch(function (error) {
                    cb(error);
                });

            } catch (err) {
                cb(err);
            }
        },
        decryptTransmission = function (message, cb, url) {
            var goOn = function (err, tab) {
                if (err) {
                    return cb(err);
                }
                decrypt(getTransmissionSecretKey(tab.url), message, cb);
            };
            if (!url) {
                getCurrentTab(goOn);
            }
            goOn(null, {url: url});
        },
        decryptSecure = function (message, cb) {
            var secretKey = getSecureSecretKey();
            if (!isSecretKeyDecrypted(secretKey)) {
                return cb(new Error('Secret-key is not decrypted'));
            }

            return decrypt(secretKey, message, cb);
        },
        verifyAndDecrypt = function (secretKey, publicKey, message, cb) { // TODO: what about verifying???
            try {
                decryptSecretKey(secretKey);
                if (!isSecretKeyDecrypted(secretKey)) {
                    return cb(new Error('Secret-key is not decrypted'));
                }
                openpgp.decryptAndVerifyMessage(secretKey, readPublicKey(publicKey), readMessage(message)).then(function (plaintext) {
                    cb(null, plaintext);
                }).catch(function (error) {
                    cb(error);
                });

            } catch (err) {
                cb(err);
            }
        },
        verifyAndDecryptTransmission = function (message, cb, url) {
            var goOn = function (err, tab) {
                if (err) {
                    return cb(err);
                }
                verifyAndDecrypt(getTransmissionSecretKey(tab.url), getTransmissionServerKey(tab.url), message, cb);
            };
            if (!url) {
                getCurrentTab(goOn);
            }
            goOn(null, {url: url});
        },

        sign = function (secretKey, message, cb) {
            'use strict';
            try {
                openpgp.signClearMessage(decryptSecretKey(secretKey), message).then(function (plaintext) {
                    cb(null, plaintext);
                }).catch(function (error) {
                    cb(error);
                });

            } catch (err) {
                cb(err);
            }
        },

        signAndEncrypt = function (secretKey, publicKey, message, cb) { // TODO: what about verifying???
            'use strict';
            try {
                openpgp.signAndEncryptMessage(readPublicKey(publicKey), decryptSecretKey(secretKey), readMessage(message)).then(function (plaintext) {
                    cb(null, plaintext);
                }).catch(function (error) {
                    cb(error);
                });

            } catch (err) {
                cb(err);
            }
        },

        createTransmissionKeys = function (cb, passphrase, url,  keyLength) {
            'use strict';

            var goOn = function () {
                var protoDomain = getProtoDomain(url), opts;
                keyLength = keyLength || 2048;

                opts = {
                    numBits: keyLength,
                    userId: publicKey[0].users[0].userId.userid.split('>').join('[transmission-' + protoDomain + ']>'),
                    passphrase: passphrase || window.prompt("Give a passphrase for new transmission key " + protoDomain)
                };

                openpgp.generateKeyPair(opts).then(function (keypair) {
                    secureSign(keypair.publicKeyArmored, function (err, sign) {
                        if (err) {
                            return cb(err);
                        }
                        localStorage.setItem('transmission-pub:' + protoDomain, keypair.publicKeyArmored);
                        localStorage.setItem('transmission-sec:' + protoDomain, keypair.privateKeyArmored);
                        localStorage.setItem('transmission-sign:' + protoDomain, sign);
                        return cb(null, {
                            secretKey: keypair.privateKeyArmored,
                            publicKey: keypair.publicKeyArmored,
                            sign: sign
                        });
                    });

                }).catch(function (error) {
                    cb(error);
                });
            };

            if (url) {
                return goOn();
            }
            chrome.tabs.getSelected(null, function (tab) {
                url = tab.url;
                goOn();
            });

        };

    exports.opengpgApi = {
        getProtoDomain: getProtoDomain,
        getCurrentTab: getCurrentTab,
        readPublicKey: readPublicKey,
        readSecretKey: readSecretKey,
        isSecretKeyDecrypted: isSecretKeyDecrypted,
        decryptSecretKey: decryptSecretKey,
        readMessage: readMessage,
        getSecurePublicKey: getSecurePublicKey,
        getTransmissionSecretKey: getTransmissionSecretKey,
        getTransmissionPublicKey: getTransmissionPublicKey,
        getTransmissionServerKey: getTransmissionServerKey,
        getTransmissionSignedPublicKey: getTransmissionSignedPublicKey,
        getSecureSecretKey: getSecureSecretKey,
        decryptSecureSecretKey: decryptSecureSecretKey,
        decryptTransmissionSecretKey: decryptTransmissionSecretKey,
        addMessage: addMessage,
        removeMessage: removeMessage,
        getMessage: getMessage,
        encrypt: encrypt,
        encryptTransmission: encryptTransmission,
        encryptSecure: encryptSecure,
        encryptSecureTransmission: encryptSecureTransmission,
        decrypt: decrypt,
        decryptTransmission: decryptTransmission,
        decryptSecure: decryptSecure,
        verifyAndDecrypt: verifyAndDecrypt,
        verifyAndDecryptTransmission: verifyAndDecryptTransmission,
        sign: sign,
        signAndEncrypt: signAndEncrypt,
        createTransmissionKeys: createTransmissionKeys
    };

}(window));
