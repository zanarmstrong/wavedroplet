"use strict";

var w = window;

function get_query_param(param) {
    var urlKeyValuePairs = {}
    window.location.href.split("#")[1].split("&").forEach(function(d) {
        var m = d.split("=");
        urlKeyValuePairs[m[0]] = m[1]
    })
    return urlKeyValuePairs[param].split(',')
}


var margin = {
        top: 20,
        right: 0,
        bottom: 10,
        left: 20
    },
    width = 1397,
    height = 1397;

var svg = d3.select("body").append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

svg.append("rect")
    .attr("class", "background")
    .attr("width", width)
    .attr("height", height);


// data structures
var dataset; // all packets, sorted by pcap_secs
var stream2packetsDict = {};
var stream2packetsArray = [];
var deviceDict = {};
var deviceCount = 0;
var deviceArray = [];

// get data & visualize
d3.json('/json/' + decodeURIComponent(get_query_param('key')[0]), function(error, json) {
    if (error) return console.error('error', error);

    init(json);
    draw();
})

function init(json) {
    // TODO(katepek): Should sanitize here? E.g., discard bad packets?
    // Packets w/o seq?
    dataset = json.js_packets;

    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    // get array of all packetSecs and use a histogram
    var packetSecs = []

    dataset.forEach(function(d) {
        replace_address_with_alias(d, json.aliases);
        // track streams
        if (d['ta'] != null) {
            d['ta'] = d['ta'].replace(/:/g, '')
        }
        if (d['ra'] != null) {
            d['ra'] = d['ra'].replace(/:/g, '')
        }
        d.streamId = to_stream_key(d, json.aliases);
        if (!stream2packetsDict[d.streamId]) {
            stream2packetsDict[d.streamId] = {
                values: [d]
            };
            stream2packetsArray.push(d.streamId);
        } else {
            stream2packetsDict[d.streamId].values.push(d);
        }

        if (!deviceDict[d['ta']]) {
            deviceDict[d['ta']] = {
                count: 1
            };
            deviceArray.push(d['ta']);
        } else {
            deviceDict[d['ta']].count++;
        }

        if (!deviceDict[d['ra']]) {
            deviceDict[d['ra']] = {
                count: 1
            };
            deviceArray.push(d['ra'])
        } else {
            deviceDict[d['ra']].count++;
        }
    })

    // sort streams by number of packets per stream
    stream2packetsArray.sort(function(a, b) {
        return stream2packetsDict[b].values.length - stream2packetsDict[a].values.length
    })

    deviceArray.sort(function(a, b) {
        return deviceDict[b].count - deviceDict[a].count
    })

    deviceArray.forEach(function(d, i) {
        deviceDict[d].order = i;
    })

}

var regexTest = /(([a-z]|[A-Z]|[0-9])+)---(([a-z]|[A-Z]|[0-9])+)/

function draw() {
    svg.selectAll('rect').data(stream2packetsArray)
        .enter().append("rect")
        .attr("class", function(d) {
            var k = d.match(regexTest)
            return "ta" + k[1] + " ra" + k[3];
        })
        .attr("width", function(d) {
            // stream2packetsDict[d].values.length
            return 1
        })
        .attr("height", function(d) {
            return 1
        })
        .attr("x", 0)
        .attr("y", 0)
        .attr("opacity", .2)
        .attr("transform", function(d, i) {
            var k = d.match(regexTest)
            return "translate(" + deviceDict[k[1]].order + " ," + deviceDict[k[3]].order + ")";
        })
        .style("fill", function(d) {
            return "blue";
        })
        .on("mouseover", mouseover)
        .on("mouseout", mouseout);;
}

function mouseover(stream) {}

function mouseout() {}


function replace_address_with_alias(d, aliases) {
    d['ta'] = aliases[d['ta']] || d['ta']
    d['ra'] = aliases[d['ra']] || d['ra']
}

function to_stream_key(d, aliases) {
    return d['ta'] + '---' + d['ra'];
}