/**
 * Created with JetBrains WebStorm.
 * User: dtudury
 * Date: 4/24/13
 * Time: 12:16 PM
 * To change this template use File | Settings | File Templates.
 */
window.onload = function () {
    require(
        ['cryptoped'],
        function (cryptoped) {

            function writeTestOutput(pbkdf2Algo, algoName, password, salt, iterations, keyLength, correctOutput) {
                var output = pbkdf2Algo(password, salt, iterations, keyLength);
                if (output == correctOutput) {
                    document.write(algoName + " PASS: " + password + "," + salt + "," + iterations + "," + keyLength + "<br/>" + output + "<br/></br>");
                } else {
                    document.write(algoName + " FAIL!: " + password + "," + salt + "," + iterations + "," + keyLength + "<br/>" + output + " != " + correctOutput + "<br/></br>");
                }
            }

            function testPbkdf2Sha2(pbkdf2Algo, algoName, callback) {
                return function () {
                    var t0 = (new Date()).getTime();

                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 1, 32,
                        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 2, 32,
                        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 4096, 32,
                        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
                    //you probably don't want to run the next few tests through cryptoJs
//                    writeTestOutput(pbkdf2Algo, algoName, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
//                        "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
//                    writeTestOutput(pbkdf2Algo, algoName, "pass\0word", "sa\0lt", 4096, 16,
//                        "89b69d0516f829893c696226650a8687");
//                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 32768, 32,
//                        "2e179fd7692d201c2ff8aec6628af50b5d637a760668767ba8c56fb36828bad7");
                    //you probably don't want to run the next test at all... (takes around 5 minutes with cryptoped)
//                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 16777216, 32,
//                        "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46");

                    var t1 = (new Date()).getTime();

                    document.write(algoName + " total runtime: <br/>" + ((t1 - t0) / 1000) + "<br/><br/><br/><br/>");
                    console.log(algoName + " test complete " + ((t1 - t0) / 1000) + "\n\n");
                    if(callback) callback();
                }

            }
            function testPbkdf2Sha1(pbkdf2Algo, algoName, callback) {
                return function () {
                    var t0 = (new Date()).getTime();

                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 1, 20,
                        "0c60c80f961f0e71f3a9b524af6012062fe037a6");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 2, 20,
                        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 4096, 20,
                        "4b007901b765489abead49d926f721d065a429c1");
//                    writeTestOutput(pbkdf2Algo, algoName, "password", "salt", 16777216, 20,
//                        "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
//                    writeTestOutput(pbkdf2Algo, algoName, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
//                        "3d2eec4fe41c849b80c8d83662c0e44a8b291a96");
//                    writeTestOutput(pbkdf2Algo, algoName, "pass\0word", "sa\0lt", 4096, 16,
//                        "56fa6aa75548099dcc37d7f03425e0c3");
                    var t1 = (new Date()).getTime();

                    document.write(algoName + " total runtime: <br/>" + ((t1 - t0) / 1000) + "<br/><br/><br/><br/>");
                    console.log(algoName + " test complete " + ((t1 - t0) / 1000) + "\n\n");
                    if(callback) callback();
                }
            }

            var cryptopedPbkdf2Sha2Algo = function (password, salt, iterations, keyLength) {
                var wordArray = cryptoped.pbkdf2(password, salt, iterations, keyLength, cryptoped.sha256);
                var output = "";
                for (var i = 0; i < wordArray.length; i++) {
                    string = (wordArray[i] >>> 0).toString(16);
                    while (string.length < 8) string = "0" + string;
                    output += string;
                }
                return output;
            }

            var cryptopedPbkdf2Sha1Algo = function (password, salt, iterations, keyLength) {
                var wordArray = cryptoped.pbkdf2(password, salt, iterations, keyLength, cryptoped.sha1);
                var output = "";
                for (var i = 0; i < wordArray.length; i++) {
                    string = (wordArray[i] >>> 0).toString(16);
                    while (string.length < 8) string = "0" + string;
                    output += string;
                }
                return output;
            }

            var cryptoJsPbkdf2Sha2Algo = function (password, salt, iterations, keyLength) {
                var keySize = 128 / 32;
                if (keyLength > 32) {
                    keySize = 512 / 32;
                } else if (keyLength > 16) {
                    keySize = 256 / 32;
                }
                var key256Bits = CryptoJS.PBKDF2(password, salt, { keySize: keySize, iterations: iterations, hasher: CryptoJS.algo.SHA256});
                return key256Bits.toString(CryptoJS.enc.Hex).slice(0, keyLength * 2);
            }

            var cryptoJsPbkdf2Sha1Algo = function (password, salt, iterations, keyLength) {
                var keySize = 128 / 32;
                if (keyLength > 32) {
                    keySize = 512 / 32;
                } else if (keyLength > 16) {
                    keySize = 256 / 32;
                }
                var key256Bits = CryptoJS.PBKDF2(password, salt, { keySize: keySize, iterations: iterations});
                return key256Bits.toString(CryptoJS.enc.Hex).slice(0, keyLength * 2);
            }


            setTimeout(testPbkdf2Sha2(cryptoJsPbkdf2Sha2Algo, "cryptoJs pbkdf2-hmac-sha256", function() {
                setTimeout(testPbkdf2Sha2(cryptopedPbkdf2Sha2Algo, "cryptoped pbkdf2-hmac-sha256", function() {
                    setTimeout(testPbkdf2Sha1(cryptoJsPbkdf2Sha1Algo, "cryptoJS pbkdf2-hmac-sha1", function() {
                        setTimeout(testPbkdf2Sha1(cryptopedPbkdf2Sha1Algo, "cryptoped pbkdf2-hmac-sha1", null), 0);
                    }), 0);
                }), 0);
            }), 0);


//            var wordArray = cryptoped.hmac("", "", cryptoped.sha1);
////            var wordArray = cryptoped.hmac("", "", cryptoped.sha256);
//            var output = "";
//            for (var i = 0; i < wordArray.length; i++) {
//                string = (wordArray[i] >>> 0).toString(16);
//                while (string.length < 8) string = "0" + string;
//                output += string;
//            }
//            console.log( output);

        }
    );
}