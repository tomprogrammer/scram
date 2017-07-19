Version 0.2.1 (2017-07-19)
==========================
Update `ring` to version `0.11` and `base64` to `0.6`.

Version 0.2.0 (2017-05-10)
==========================

* *New feature:* A SCRAM server implementation contributed by dyule. Thanks!
* Rename `client::ClientFirst` to `client::ScramClient`. The former is deprecated, but keeps working
  in the v0.2 series.
* Reexport `ScramClient`, `ScramServer` and other often used structs at crate root.
* Update `ring` to version `0.9.4`.
* Replace dependency on `data_encoding` by the `base64` crate.

Version 0.1.1 (2017-01-30)
==========================
Update `ring` to version `0.6`.

Version 0.1.0 (2016-08-24)
==========================
Version numbers like `0.0.x` are non-compatible, using `0.1.0` allows to push minior updates.

Version 0.0.2 (2016-08-24)
==========================
Update `ring` to version `0.3.0`.

Version 0.0.1 (2016-08-20)
==========================
First release providing a SCRAM-SHA-256 client implementation without support for channel-binding.
