// Cantilever.Core.X509.Validity FFI implementation
// Time conversions and system clock access
export const nowEpochSecondsImpl = function() {
  return Math.floor(Date.now() / 1000);
};

export const parseTimeStringToEpochSecondsImpl = function(just, nothing, str) {
  try {
    const s = str.trim();
    let year = 0;
    let month = 0;
    let day = 0;
    let hour = 0;
    let min = 0;
    let sec = 0;

    if (s.length === 13 && s.endsWith("Z")) {
      // UTCTime: YYMMDDHHMMSSZ
      let yy = parseInt(s.substr(0, 2), 10);
      year = yy >= 50 ? 1900 + yy : 2000 + yy;
      month = parseInt(s.substr(2, 2), 10);
      day = parseInt(s.substr(4, 2), 10);
      hour = parseInt(s.substr(6, 2), 10);
      min = parseInt(s.substr(8, 2), 10);
      sec = parseInt(s.substr(10, 2), 10);
    } else if (s.length === 15 && s.endsWith("Z")) {
      // GeneralizedTime: YYYYMMDDHHMMSSZ
      year = parseInt(s.substr(0, 4), 10);
      month = parseInt(s.substr(4, 2), 10);
      day = parseInt(s.substr(6, 2), 10);
      hour = parseInt(s.substr(8, 2), 10);
      min = parseInt(s.substr(10, 2), 10);
      sec = parseInt(s.substr(12, 2), 10);
    } else {
      return nothing;
    }

    const d = new Date(Date.UTC(year, month - 1, day, hour, min, sec));
    return just(Math.floor(d.getTime() / 1000));
  } catch (e) {
    return nothing;
  }
};

export const formatEpochSecondsToAsn1TimeImpl = function(epochSec) {
  const d = new Date(epochSec * 1000);
  const year = d.getUTCFullYear();
  const pad = (n) => (n < 10 ? "0" + n : "" + n);
  const mm = pad(d.getUTCMonth() + 1);
  const dd = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const min = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());

  if (year >= 1950 && year < 2050) {
    // UTCTime
    const yy = pad(year % 100);
    return {
      isUtcTime: true,
      timeString: `${yy}${mm}${dd}${hh}${min}${ss}Z`
    };
  } else {
    // GeneralizedTime
    return {
      isUtcTime: false,
      timeString: `${year}${mm}${dd}${hh}${min}${ss}Z`
    };
  }
};
