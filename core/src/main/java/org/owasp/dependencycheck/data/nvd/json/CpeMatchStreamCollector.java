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
import java.util.Set;

import org.owasp.dependencycheck.utils.HdivUtils.BiConsumer;
import org.owasp.dependencycheck.utils.HdivUtils.BinaryOperator;
import org.owasp.dependencycheck.utils.HdivUtils.Collector;
import org.owasp.dependencycheck.utils.HdivUtils.Supplier;
import org.owasp.dependencycheck.utils.HdivUtils.Function;

/**
 *
 * @author Jeremy Long
 */
public class CpeMatchStreamCollector implements Collector<DefNode, ArrayList<DefCpeMatch>, ArrayList<DefCpeMatch>> {

    @Override
    public Supplier<ArrayList<DefCpeMatch>> supplier() {
        return new Supplier<ArrayList<DefCpeMatch>>() {

			@Override
			public ArrayList<DefCpeMatch> get() {
				return new ArrayList<>();
			}
		};
    }

    @Override
    public BiConsumer<ArrayList<DefCpeMatch>, DefNode> accumulator() {
    	return new BiConsumer<ArrayList<DefCpeMatch>, DefNode>() {

			@Override
			public void accept(ArrayList<DefCpeMatch> t, DefNode u) {
				t.addAll(u.getCpeMatch());
			}
		};
    }

    @Override
    public BinaryOperator<ArrayList<DefCpeMatch>> combiner() {
    	return new BinaryOperator<ArrayList<DefCpeMatch>>() {
    		public ArrayList<DefCpeMatch> apply(ArrayList<DefCpeMatch> map, ArrayList<DefCpeMatch> other) {
    			map.addAll(other);
                return map;
    		}
    		
    	};
    }

    @Override
    public Function<ArrayList<DefCpeMatch>, ArrayList<DefCpeMatch>> finisher() {
    	return new Function<ArrayList<DefCpeMatch>, ArrayList<DefCpeMatch>>() {

			@Override
			public ArrayList<DefCpeMatch> apply(ArrayList<DefCpeMatch> t) {
				return t;
			}
    		
    	};
    }


}
