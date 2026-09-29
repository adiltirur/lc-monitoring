// Shared by the analytics, cockpit-analytics and historical-export routes.

// Status enum values that mean "did NOT take place" — used to filter
// "Took Place" queries so cancellations / no-shows / fake admin rows don't
// inflate the count. Indices match CoreAppUserAppointmentStatus from the
// Serverpod yaml (mirrored in public/index.html APT_STATUS):
//   5 = cancelled, 6 = noshow, 7 = enteredInError.
// Other statuses (booked / arrived / fulfilled / rescheduled / checkedIn /
// waitlist / proposed / pending) are kept — for past startTimes they mean
// "happened or was intended to happen at this time".
const DID_NOT_TAKE_PLACE_STATUSES = '(5, 6, 7)';
const TOOK_PLACE_STATUS_FILTER    = `AND status NOT IN ${DID_NOT_TAKE_PLACE_STATUSES}`;

// Cockpit constants (also used by the historical export).
const BUNDESLAND_CODES = ['bw','by','be','bb','hb','hh','he','mv','ni','nw','rp','sl','sn','st','sh','th'];
const COCKPIT_KIND_NAMES = ['vorOrt','homeoffice','akut','heimversorgung','urlaub','nichtBuchbar','buffer'];
const COCKPIT_DAY_NAMES = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'];

function currentIsoYearWeek(d = new Date()) {
  const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t - yearStart) / 86400000 + 1) / 7);
  return { year: t.getUTCFullYear(), week };
}

module.exports = { BUNDESLAND_CODES, COCKPIT_DAY_NAMES, COCKPIT_KIND_NAMES, TOOK_PLACE_STATUS_FILTER, currentIsoYearWeek };
