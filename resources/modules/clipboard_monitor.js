function clipRun(runTime){
	ObjC.import('AppKit');
	let cboard = [];
	let pb = $.NSPasteboard.generalPasteboard;
	let count = 0;
	//console.log(count);
	for (let i = 0; i < runTime; i++){
		//console.log(pb.changeCount);
		if (count < pb.changeCount){
			//console.log("New data on clipboard!: ");
			//console.log(pb.stringForType("NSStringPboardType").js);
		    cboard.push(pb.stringForType("NSStringPboardType").js);
			count = pb.changeCount;
		}
		$.NSThread.sleepForTimeInterval(1);
	}
	return cboard.toString();
}
let runTime = %s;
clipRun(runTime);