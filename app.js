const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const viewRouter = require('./routes/viewRoutes');

const app = express();

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

// 1) GLOBAL MIDDLEWARES
// Serving static files
app.use(express.static(path.join(__dirname, 'public')));

// Set security HTTP headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': [
          //       'useDefaults: true',
          "'self'",
          "'unsafe-inline'",
          'unsafe-eval',
          //       'https://*.fonts.googleapis.com/css',
          'http://localhost:3000/dc197738-50f2-450e-b89f-850ece4545d8',
          'http://localhost:3000/js/bundle.js',
          'https://js.stripe.com/v3/',
          // 'https://api.mapbox.com/mapbox-gl-js/v0.54.0/mapbox-gl.js',
          'http://localhost:3000/1a36e7f4-4bf4-458e-93cd-0e4908cf257d',
          'http://localhost:3000/aef7c947-c2dc-4b61-8fdc-8086c1d3dcbc',
          'http://localhost:3000/f677b7fa-1236-4772-86fb-8cb3902812e6',
          'http://localhost:3000/67db34b9-8266-42a6-8c93-a82c766e1fce',
          'http://localhost:3000/5d8e0b21-9643-4fb4-b782-eebeae285e10',
          'http://localhost:3000/886dc037-4fbb-416b-9da6-0965100c1d1b',
          'http://localhost:3000/f12ab04b-bb08-48c0-95fa-3e0796c302a7',
          'http://localhost:3000/9f4ccc0c-d076-40b9-a342-d7f2fce6f40a',
          'https://api.mapbox.com/mapbox-gl-js/v2.3.1/mapbox-gl.js',
          'http://localhost:3000/js/bundle.js',
          'http://localhost:3000/js//bundle.js.map',
          'http://localhost:3000/3d5733b5-17c1-492d-910f-1c8da3680017',
          'http://localhost:3000/7d95c918-5428-47d6-891c-777defe86715',
          'http://localhost:3000/691b717c-c851-4ab1-b94f-f4f13c6dbb84',
          'http://localhost:3000/f9a12e68-14f6-4fcd-a706-0faabafaa678',
          'http://localhost:3000/5287e670-5441-405c-a1cf-32ba7f320f56',
          'http://localhost:3000/59e0dd25-661d-4280-b523-5342bd5a2cef',
          'http://localhost:3000/3d08861f-3360-4b1d-89d3-2e32bccc38ae',
          'http://localhost:3000/12a1f73d-28e3-4107-9790-637db772c6c6',
          'http://localhost:3000/0365d272-85af-44bc-b3fc-925fe9728f00',
          'http://localhost:3000/7d446d76-ec35-4d46-8fd2-149d531d8137',
          'http://localhost:3000/53e57057-1f11-40cf-bf35-b66e3b0fe596',
          'http://localhost:3000/6440dad5-682c-436b-8688-438e6bb327dd',
          'http://localhost:3000/241756d0-8364-4842-9c77-574e6776521d',
          'http://localhost:3000/d76e1749-afd5-4afc-9e22-7bb8871831e6',
          'http://localhost:3000/d6a1ddec-2c33-4b05-ba5c-6da3b83c9050',
          // 'http://localhost:3000/js/bundle.js',
          'https://js.stripe.com/v3/m-outer-5564a2ae650989ada0dc7f7250ae34e9.html#url=http%3A%2F%2Flocalhost%3A3000%2F&title=Natours%20%7C%20All%20Tours&referrer=&muid=NA&sid=NA&version=6&preview=false',
          //       // 'ws://localhost:58766',
          'http://localhost:3000/e8feba58-2a59-4112-a6a9-7f258358174b',
        ],
        'style-src': [
          "'self'",
          //       'unsafe-eval',
          "'unsafe-inline'",
          //       // 'https://api.mapbox.com/mapbox-gl-js/v2.3.1/mapbox-gl.js',
          // 'https://api.mapbox.com/styles/v1/uttkarsh123/ckssuamej0q8217tbrtho3dr3?access_token=pk.eyJ1IjoidXR0a2Fyc2gxMjMiLCJhIjoiY2tzc3Rka3l4MDdxYTJ4b2ZucjRtbGozbSJ9.XPDoZvvT9w9FZaPD6xvHjw',
          //       'https://*.js.stripe.com/v3/',
          //       'https://api.mapbox.com/mapbox-gl-js/v0.54.0/mapbox-gl.css',
          'https://fonts.googleapis.com',
          //       'http://*.localhost:3000/js/bundle.js',
          'https://api.mapbox.com/mapbox-gl-js/v2.3.1/mapbox-gl.css',
          'https://js.stripe.com/v3/',
          'http://localhost:3000/css/style.css',

          // 'http://localhost:3000/css/style.css',
        ],
        //     'font-src': [
        //       "'self'",
        //       "'unsafe-inline'",
        //       'https://fonts.googleapis.com/',
        //       'https://fonts.gstatic.com/',
        //       'https://fonts.googleapis.com/css',
        //     ],
        'img-src': [
          "'self'",
          //       // 'unsafe-eval',
          //       "'unsafe-inline'",
          'http://localhost:3000/4b5d3ad5-30a7-4d94-a0ab-780f0ddb1094',
          'http://localhost:3000/img/',
          'http://localhost:3000/7a5e883e-adee-4848-86bd-561f79a0c30a',
        ],
        'connect-src': [
          "'self'",
          //       'unsafe-eval',
          //       "'unsafe-inline'",
          //       'https://js.stripe.com/v3/m-outer-5564a2ae650989ada0dc7f7250ae34e9.html#url=http%3A%2F%2Flocalhost%3A3000%2Ftour%2Fthe-sea-explorer&title=Natours%20%7C%20The%20Sea%20Explorer%20Tour&referrer=&muid=NA&sid=NA&version=6&preview=false',
          'https://api.mapbox.com/',
          'https://events.mapbox.com',
          'http://localhost:58766/',

          //       'https://localhost:58766',
        ],
        //     'frame-src': [
        //       "'self'",
        //       "'unsafe-inline'",
        //       'https://js.stripe.com/',
        //       'https://api.mapbox.com/',
        //     ],
        //     'object-src': [
        //       "'self'",
        //       "'unsafe-inline'",
        //       'blob:http://localhost:3000/e8feba58-2a59-4112-a6a9-7f258358174b',
        // ],
        'default-src': [
          "'self'",
          //       "'unsafe-inline'",
          //       'https://js.stripe.com/',
          'https://api.mapbox.com/',
          'https://js.stripe.com/v3/m-outer-5564a2ae650989ada0dc7f7250ae34e9.html#url=http%3A%2F%2Flocalhost%3A3000%2Ftour%2Fthe-sea-explorer&title=Natours%20%7C%20The%20Sea%20Explorer%20Tour&referrer=&muid=6735fca6-4a75-4b3d-862a-abc8675380452f3f08&sid=bd03cc76-3cdf-4fee-9f22-48102ca05ca399428a&version=6&preview=false',
          'http://localhost:3000/img/icons.svg',

          //'https://api.mapbox.com/styles/v1/uttkarsh123/ckssuamej0q8217tbrtho3dr3?access_token=pk.eyJ1IjoidXR0a2Fyc2gxMjMiLCJhIjoiY2tzc3Rka3l4MDdxYTJ4b2ZucjRtbGozbSJ9.XPDoZvvT9w9FZaPD6xvHjw',
        ],
      },
    },
  })
);

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from same API
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!',
});
app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsQuantity',
      'ratingsAverage',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  })
);

// Test middleware
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  console.log(req.cookies);
  next();
});

// 3) ROUTES
app.use('/', viewRouter);
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
