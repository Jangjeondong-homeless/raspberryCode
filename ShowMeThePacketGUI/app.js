var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();
// var http = require('http').Server(app);

app.io = require('socket.io')();

// view engine setup

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');



// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// app.set('port', process.env.PORT || 3000);
// app.get('/', function(req, res) {
//     res.sendFile(__dirname + '/views/index.jade');
// });
//
// http.listen(3000, function(){
//     console.log('listening on *:3000');
// });
// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


app.io.on('connection', function(socket){
    socket.on('chat message', function(msg){
        app.io.emit('chat message', msg);
    });
});


var mysql = require('mysql');

// var connection = mysql.createConnection({
//     host     : 'ec2-54-250-137-190.ap-northeast-1.compute.amazonaws.com',
//     user     : 'root',
//     port     : 3306,
//     database : 'snort'
// });

var connection = mysql.createConnection({
    host     : '192.168.200.176',
    user     : 'root',
    password : '1234',
    port     : 3306,
    database : 'snort'
});

connection.connect();

Date.prototype.toMySQLDateTime = function () {
    function addZ(n) {
        return (n<10? '0' : '') + n;
    }
    return this.getFullYear() + '-' +
        addZ(this.getMonth() + 1) + '-' +
        addZ(this.getDate()) + ' ' +
        addZ(this.getHours()) + ':' +
        addZ(this.getMinutes()) + ':' +
        addZ(this.getSeconds());
};

var today = new Date();
var lastCreated = today.toMySQLDateTime();
var valid_attacked_count = 0;
var total_attacked_count = 0;
var log_count = 0;



setInterval(function(){
    var sql = "SELECT * from event WHERE timestamp > '" + lastCreated + "' ORDER BY timestamp";
    // var sql = "SELECT * FROM event";
    connection.query(sql, function (err, rows, fields) {
        if (!err) {

            var rowsLength = rows.length;
            if(rowsLength) {
                var get_total_count = "SELECT count(sid) from event";
                connection.query(get_total_count, function (err, rows){
                    app.io.emit('total_attacked_count',total_attacked_count += rows[0]['count(sid)'] );
                });

                lastCreated = (rows[rowsLength-1].timestamp).toMySQLDateTime();
                app.io.emit('log_count',log_count += rowsLength);

                var get_event_info = "select a.* from signature a, event b where a.sig_id = b.signature";
                connection.query(get_event_info, function(err, log){
                    if(err) console.log(err);
                    else {
                        app.io.emit('detected_attack_log',log);
                    }
                });

                for(var iter = 0; iter < rowsLength; iter+=4) {

                    var get_sid = " (SELECT sig_sid FROM signature WHERE sig_id = "
                        + rows[iter].signature + ") ";
                    var log_sql = "SELECT a.*, b.* FROM sid_cve_os a, signature b WHERE a.sid = " + get_sid
                        + " and b.sig_id = " + rows[iter].signature;
                    // console.log(log_sql);

                    connection.query(log_sql, function(err, log, fields) {
                        if(err) console.log(err);
                        else {

                            app.io.emit('DATA', log);
                        }
                    });

                    var log_sql = "SELECT * FROM sid_cve_os WHERE sid = " + get_sid;

                    connection.query(log_sql, function(err, log, fields) {
                        if(err) console.log(err);
                        else {
                            app.io.emit('DATA', log);
                        }
                    });

                    var valid_attack_sql = "select a.*, b.*, c.* from internal_ip_list a, sid_cve_os b, signature c"
                        + " where (a.os = (select b.os from sid_cve_os b where b.sid =  " + get_sid + " group by b.os) and "
                        + " a.flavor = (select b.flavor from sid_cve_os b where b.sid =  " + get_sid + " group by b.flavor) and "
                        + " b.sid = " + get_sid
                        + "and c.sig_id = " + rows[iter].signature + ")";
                    // console.log(valid_attack_sql);
                    connection.query(valid_attack_sql,function(err, rows) {
                        if(err) console.log(err);
                        else if (rows.length){
                            app.io.emit('valid_attacked_count', valid_attacked_count += rows.length);
                            // console.log(rows);
                            app.io.emit('valid_attack_info',rows);
                        }
                    });
                }
            }
        }
        else {
            console.log('Error while performing Query.', err);
        }
    });

    // var internal_ip_sql = "SELECT * FROM internal_ip_list WHERE update_time >= DATE_ADD(NOW(), INTERVAL -12 HOUR)";
    var internal_ip_sql = "SELECT * FROM internal_ip_list";
    connection.query(internal_ip_sql,function(err, rows, fields) {
        if(err) console.log(err);
        else {
          app.io.emit('internal_ip_list',rows);
        }
    });


    // var internal_os_sql = "SELECT os, flavor FROM internal_ip_list WHERE update_time >= DATE_ADD(NOW(), INTERVAL -12 HOUR) GROUP BY os, flavor";
    var internal_os_sql = "SELECT os, flavor FROM internal_ip_list GROUP BY os, flavor";
    connection.query(internal_os_sql,function(err, rows, fields) {
        if(err) console.log(err);
        else {
            app.io.emit('internal_os_list',rows);
        }
    });
},1000);



module.exports = app;
