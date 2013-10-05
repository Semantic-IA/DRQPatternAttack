'''
Parallelize a task

@author: Max Maass
'''
import multiprocessing
import var.Config


def parallelize(attackerFunction, generatorFunction, args, ProgressBarInstance):
    '''Parallelize the call of targetFunction into count subprocesses

    @param targetFunction: The function to call
    @param args: The argument to the function (only one argument supported)
    @param count: The number of Subprocesses to be spawned
    @return: The merged results of the function
    '''
    res_queue = multiprocessing.Queue() # Create a threadsafe queue for the results
    res_dict = {}   # Create a result dictionary
    processes = []  # Prepare the process list
    part = int(len(args)/var.Config.THREADS)
    # Determine the split of the input values to distribute them across all processes
    for i in range(var.Config.THREADS): # Now we will reate var.Config.THREADS processes
        if i != var.Config.THREADS-1: # If this is not the last process to be created...
            arg = args[i*part:(i+1)*part] # Start it with this part of the input data
        else:
            arg = args[i*part:] # Else give it the remaining input values to make sure none are left out
        p = multiprocessing.Process(target=catchResult, args=(attackerFunction(), \
            generatorFunction(), arg, res_queue, ProgressBarInstance))
        # Prepare a process that will run the catchResult-function with the provided arguments.
        processes.append(p) # Add it to the process list for later process management...
        p.start() # ...and run it.
    for i in processes:
        res_dict.update(res_queue.get()) # Get all results from all processes and save them
    for p in processes:
        p.join() # Wait for all processes to exit
    return res_dict # Return the result dictionary


def catchResult(attackerInstance, generatorInstance, args, res_queue, ProgressBarInstance):
    '''Catch the results the called function provides and add them to the result_queue

    @param attackerInstance: a attacker instance
    @param generatorInstance: a generator instance
    @param args: The List of Arguments that should be interated through
    @param res_queue: The queue in which to save the results (Results are saved as one dictionary and submitted in the end)
    @param ProgressBarInstance: The instance of the progress bar that should be updated
    @return: A dictionary mapping attacker arguments to results
    '''
    try:
        resdict = {}
        for arg in args:
            resdict[arg] = attackerInstance.attack(generatorInstance.generateDRQFor(arg))
            # Run an attack on an input value
            ProgressBarInstance.tick() # Update progress bar
        res_queue.put(resdict) # return result dictionary
        return 0
    except KeyboardInterrupt: # Exit on Ctrl+C
        return 1
    except Exception as e: # Catch and log exceptions
        print "Parallel: Catch Result: Uncaught Exception"
        print "Details:", type(e)
        print e
        return 2
