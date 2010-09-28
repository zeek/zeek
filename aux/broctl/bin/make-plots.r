
# $Id: make-plots.r 6813 2009-07-07 18:54:12Z robin $

# Text & pch scaling.
scale.cex		<- 1.4 
scale.cex.lab	<- 1.4
scale.cex.legend <- 1.0

# Parameters for nicer plotting
sample <- 10
num <- 50 
shift <- 0

plotLoad <- function(tag, host, key, style, factor=1)
{                       
    file <- paste(tag, ".", host, ".dat", sep="")
    data <- read.table(file, header=TRUE)
    print(file)

    times <- data$time
    vals  <- data[[key]] / factor

	l <- xy.coords(times, vals)
    l$x = l$x[seq(1, length(l$x), by=sample)]
	l$y = l$y[seq(1, length(l$y), by=sample)]
	p <- seq(1 + shift * length(l$x) / num, length(l$x), length=num)
	lines(l$x, l$y, col=style)
	points(l$x[p], l$y[p], col=style, pch=style)
}

plotSeries <- function(tag, hosts, type, factor=1)
{
   	style <- 1
    labels <- c()
    for ( i in seq(1, length(hosts)) ) {
        plotLoad(tag, hosts[i], type, style, factor=factor)
        style <- style + 1
        labels <- c(labels, hosts[i])
        }

    lsize <- length(labels)
    cornerLegend(legend=labels, col=c(1:lsize), lty=1, pch=c(1:lsize), corner=2, cex=scale.cex.legend, ncol=5)
    dev.off()
}


plotScale <- function(file, tag, host, ymax, title, xlab, ylab)
{
 	postscript(file, paper="special", width=11, height=6.5)    
    par(cex=1.3)
    file <- paste(tag, ".", host, ".dat", sep="")
    data <- read.table(file, header=TRUE)

    times <- data$time

 	timeplot(c(min(times), max(times)), c(0, ymax), type="n", xlab=xlab, ylab=ylab, timezone=7, main=title)
}

########## Stolen from Holger #######################

weekdays<-c("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
weekdaysLong<-c("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")

time2str<-function(unixt, timezone=1)
{
	t<-timestamp(unixt, timezone)
	s<-weekdays[t[1]+1]
	s<-paste(s, t[2], sep=" ")
	s<-paste(s, sprintf("%02g", t[3]), sep=":")
	s
}

timeticks <- function (start, end, tickdist=NULL, labeldist=NULL, offset=1, timezone=1)
{
	if(identical(tickdist,NULL)) 
		tickdist<-timetickdist(start, end)
	if(identical(labeldist, NULL)) 
		labeldist<-tickdist
	pos<-start-1
	res=list(ticks=c(), labels=c())
	while(pos < end)
	{
		pos<-nexttick(pos, tickdist, offset)
		if(pos<=end)
		{
			res$ticks<-c(res$ticks, pos)
			if (identical((pos+offset*3600)%%labeldist,0)) 
				res$labels<-c(res$labels, time2str(pos, timezone=offset)) 
			else 
				res$labels<-c(res$labels, " ")

		}
	}
	res
}

nexttick <- function (cur, dist, offset=1) 
{
	nextt <- cur
	curTZ = cur+offset*3600
	if (identical(curTZ%%dist,0)) 
		nextt <- cur+dist 
	else 
		nextt <- cur+(dist-(curTZ%%dist))

	nextt
}

timetickdist <- function (start, end)
{
  d <- end-start
  tickdist <- 3600*24
  if (d<=3600*24*7) tickdist<-3600*12
  if (d<=3600*24*3) tickdist<-3600*6
  if (d<=3600*24) tickdist<-3600*2
  if (d<=3600*12) tickdist<-3600
  if (d<=3600) tickdist<-15*60
  tickdist
}

cet <- function (unixt)
{
	timestamp(unixt, 1)
}

timestamp<-function (unixt, offset)
{
	unixt<-floor(unixt)
	secs<-unixt%%60
	unixt<-unixt%/%60
	mins<-unixt%%60
	unixt<-(unixt%/%60) + offset
	hrs<-unixt%%24
	unixt<-unixt%/%24
	days<-(unixt-3)%%7 
	c(days,hrs,mins,secs)
}

timeaxis <- function(xrange, offset=1, labels=T, timezone=1)
{
	t <- timeticks(xrange[1], xrange[2], offset=offset, timezone=timezone)
	if (labels) 
		axis(1, at=t$ticks, labels=t$labels)
	else 
		axis(1, at=t$ticks, labels=F)
}

timeplot <- function(x, y, offset=1, labels=T, timezone=1, ...)
{
	plot(x, y, axes=F, ...)
	box()
	axis(2)
	timeaxis(range(x), offset, labels, timezone=timezone)
}

cornerLegend<-function(corner = 1, xoffs=0, yoffs=0, ...) {
	xalign = 0
		yalign = 0
		smoothf=c(1,1)
		if (corner == 1){
			corner<-c(par()$usr[1], par()$usr[3])
				xalign = 0
				yalign = 0
		}else if (corner == 2){
			corner<-c(par()$usr[1], par()$usr[4])
				xalign = 0
				yalign = 1
				smoothf=c(1,-1)
		}else if (corner == 3){
			corner<-c(par()$usr[2], par()$usr[4])
				xalign = 1
				yalign = 1
				smoothf= c(-1,-1)
		}else{
			corner<-c(par()$usr[2], par()$usr[3])
				xalign = 1
				yalign = 0
				smoothf = c(-1,1)
		}

	cat(corner, "\n")

		smooth<-c(0,0)
		if(par("xlog")){
			corner[1]<-10^corner[1]
				smooth[1]<-0
		}else{
			smooth[1]<-(par("usr")[2]-par("usr")[1])/50
		}
	if(par("ylog")){
		corner[2]<-10^corner[2]
			smooth[2]<-(10^par("usr")[4]-10^par("usr")[3])/-50
	}else{
		smooth[2]<-(par("usr")[4]-par("usr")[3])/50
	}
	smooth<-smooth*smoothf
		cat (smooth, "\n")
		legend(x=corner[1]+smooth[1]+xoffs, y=corner[2]+smooth[2]+yoffs, xjust=xalign, yjust=yalign, ...)
}

########## End of Stolen from Holger #######################

# Interface statistics

hosts <- read.table("interface.hosts.dat", header=TRUE, as.is=TRUE)$name
plotScale("bandwith.eps", "interface", hosts[1], 500, "Bandwidth", "Time", "Mbps")
plotSeries("interface", hosts, "mbps")

# CPU Load Child Process

hosts <- read.table("child.hosts.dat", header=TRUE, as.is=TRUE)$name
plotScale("cpu-child.eps", "child", hosts[1], 120, "CPU Load - Child Process", "Time", "Load")
plotSeries("child", hosts, "cpu")

# CPU Load Parent Process

hosts <- read.table("parent.hosts.dat", header=TRUE, as.is=TRUE)$name
plotScale("cpu-parent.eps", "parent", hosts[1], 120, "CPU Load - Parent Process", "Time", "Load")
plotSeries("parent", hosts, "cpu")

# Memory Parent Process

hosts <- read.table("parent.hosts.dat", header=TRUE, as.is=TRUE)$name
plotScale("mem-parent.eps", "parent", hosts[1], 2, "Memory - Parent Process", "Time", "GBytes")
plotSeries("parent", hosts, "vsize", factor=1024*1024*1024)

# Memory Child Process

hosts <- read.table("child.hosts.dat", header=TRUE, as.is=TRUE)$name
plotScale("mem-child.eps", "child", hosts[1], 2, "Memory - Child Process", "Time", "GBytes")
plotSeries("child", hosts, "vsize", factor=1024*1024*1024)

