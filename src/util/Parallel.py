'''
Parallelize a task

@author: Max Maass
'''
# TODO: More Docs
# TODO: Find out why the progress bar seems to bug out on -m 3 -t 4 --all
import multiprocessing
import var.Config


def parallelize(attackerFunction, generatorFunction, args, ProgressBarInstance):
    '''Parallelize the call of targetFunction into count subprocesses

    @param targetFunction: The function to call
    @param args: The argument to the function (only one argument supported)
    @param count: The number of Subprocesses to be spawned
    @return: The merged results of the function
    '''
    res_queue = multiprocessing.Queue()
    res_dict = {}
    processes = []
    part = int(len(args)/var.Config.THREADS)
    for i in range(var.Config.THREADS):
        if i != var.Config.THREADS-1:
            arg = args[i*part:(i+1)*part]
        else:
            arg = args[i*part:]
        p = multiprocessing.Process(target=catchResult, args=(attackerFunction(), generatorFunction(), arg, res_queue, ProgressBarInstance))
        processes.append(p)
        p.start()
    for i in processes:
        res_dict.update(res_queue.get())
    for p in processes:
        p.join()
    return res_dict


def catchResult(attackerInstance, generatorInstance, args, res_queue, ProgressBarInstance):
    '''Catch the results the called function provides and add them to the result_queue

    @param targetFunction: the function to call
    @param args: The List of Arguments in the format [["domain_name",[pattern]],["domain_name",[pattern]],...]
    @param res_queue: The queue in which to save the results (Results are saved as one dictionary and submitted in the end)
    '''
    try:
        resdict = {}
        for arg in args:
            resdict[arg] = attackerInstance.attack(generatorInstance.generateDRQFor(arg))
            ProgressBarInstance.tick()
        res_queue.put(resdict)
        return 0
    except KeyboardInterrupt:
        return 1
