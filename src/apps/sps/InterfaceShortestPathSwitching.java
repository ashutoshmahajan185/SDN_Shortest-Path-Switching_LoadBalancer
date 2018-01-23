package edu.brown.cs.sdn.apps.sps;
/*
Ashutosh Mahajan
N15565485
abm523
*/
import net.floodlightcontroller.core.module.IFloodlightService;

public interface InterfaceShortestPathSwitching extends IFloodlightService {
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable();
}
