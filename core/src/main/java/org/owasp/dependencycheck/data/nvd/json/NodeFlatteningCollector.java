/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.json;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.owasp.dependencycheck.utils.HdivUtils.BiConsumer;
import org.owasp.dependencycheck.utils.HdivUtils.BinaryOperator;
import org.owasp.dependencycheck.utils.HdivUtils.Collector;
import org.owasp.dependencycheck.utils.HdivUtils.Function;
import org.owasp.dependencycheck.utils.HdivUtils.Supplier;

/**
 * Used to flatten a hierarchical list of nodes with children.
 *
 * @author Jeremy Long
 */
public class NodeFlatteningCollector implements Collector<DefNode, ArrayList<DefNode>, ArrayList<DefNode>> {

    /**
     * Flattens the hierarchical list of nodes.
     *
     * @param node the node with children to flatten
     * @return the flattened list of nodes
     */
    private List<DefNode> flatten(DefNode node) {
        final List<DefNode> result = new ArrayList<>();
        result.add(node);
        return flatten(result, node.getChildren());
    }

    /**
     * Flattens the hierarchical list of nodes.
     *
     * @param result the results
     * @param nodes the nodes
     * @return the flattened list of nodes
     */
    private List<DefNode> flatten(List<DefNode> result, List<DefNode> nodes) {
    	for (DefNode defNode : nodes) {
    		flatten(result, defNode.getChildren());
            result.add(defNode);
		}

        return result;
    }

    @Override
    public Supplier<ArrayList<DefNode>> supplier() {
    	return new Supplier<ArrayList<DefNode>>() {

			@Override
			public ArrayList<DefNode> get() {
				return new ArrayList<>();
			}
		};
    }

    @Override
    public BiConsumer<ArrayList<DefNode>, DefNode> accumulator() {
    	return new BiConsumer<ArrayList<DefNode>, DefNode>() {

			@Override
			public void accept(ArrayList<DefNode> t, DefNode u) {
				t.addAll(flatten(u));
			}
		};
    }

    @Override
    public BinaryOperator<ArrayList<DefNode>> combiner() {
    	return new BinaryOperator<ArrayList<DefNode>>() {

			@Override
			public ArrayList<DefNode> apply(ArrayList<DefNode> map, ArrayList<DefNode> other) {
				map.addAll(other);
	            return map;
			}
		};
    }

    @Override
    public Function<ArrayList<DefNode>, ArrayList<DefNode>> finisher() {
    	return new Function<ArrayList<DefNode>, ArrayList<DefNode>>() {

			@Override
			public ArrayList<DefNode> apply(ArrayList<DefNode> t) {
				return t;
			}
    		
    	};
    }

}
